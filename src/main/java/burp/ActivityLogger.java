package burp;

import java.net.InetAddress;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.extension.ExtensionUnloadingHandler;

/**
 * Handle the recording of the activities into the real storage, SQLite local DB here.
 * Now uses async writes with a background thread for improved performance.
 */
class ActivityLogger implements ExtensionUnloadingHandler {

    /**
     * SQL instructions.
     */
    private static final String SQL_TABLE_CREATE = "CREATE TABLE IF NOT EXISTS ACTIVITY (LOCAL_SOURCE_IP TEXT, TARGET_URL TEXT, HTTP_METHOD TEXT, BURP_TOOL TEXT, REQUEST_RAW TEXT, SEND_DATETIME TEXT, HTTP_STATUS_CODE TEXT, RESPONSE_RAW TEXT)";
    private static final String SQL_TABLE_INSERT = "INSERT INTO ACTIVITY (LOCAL_SOURCE_IP,TARGET_URL,HTTP_METHOD,BURP_TOOL,REQUEST_RAW,SEND_DATETIME,HTTP_STATUS_CODE,RESPONSE_RAW) VALUES(?,?,?,?,?,?,?,?)";
    private static final String SQL_COUNT_RECORDS = "SELECT COUNT(HTTP_METHOD) FROM ACTIVITY";
    private static final String SQL_TOTAL_AMOUNT_DATA_SENT = "SELECT TOTAL(LENGTH(REQUEST_RAW)) FROM ACTIVITY";
    private static final String SQL_BIGGEST_REQUEST_AMOUNT_DATA_SENT = "SELECT MAX(LENGTH(REQUEST_RAW)) FROM ACTIVITY";
    private static final String SQL_MAX_HITS_BY_SECOND = "SELECT COUNT(REQUEST_RAW) AS HITS, SEND_DATETIME FROM ACTIVITY GROUP BY SEND_DATETIME ORDER BY HITS DESC";

    /**
     * Maximum queue size to prevent memory issues
     */
    private static final int MAX_QUEUE_SIZE = 10000;
    
    /**
     * Batch size for database writes
     */
    private static final int BATCH_SIZE = 100;
    
    /**
     * Maximum wait time for batch processing (milliseconds)
     */
    private static final long BATCH_TIMEOUT_MS = 1000;

    /**
     * Use a single DB connection for performance and to prevent DB file locking issue at filesystem level.
     */
    private Connection storageConnection;

    /**
     * DB URL
     */
    private String url;

    /**
     * Ref on project logger.
     */
    private Trace trace;

    /**
     * Formatter for date/time.
     */
    private DateTimeFormatter datetimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /**
     * Queue for async event processing
     */
    private final BlockingQueue<LogEvent> eventQueue = new LinkedBlockingQueue<>(MAX_QUEUE_SIZE);
    
    /**
     * Background thread for database writes
     */
    private Thread writerThread;
    
    /**
     * Flag to control the writer thread lifecycle
     */
    private final AtomicBoolean running = new AtomicBoolean(true);

    /**
     * Constructor.
     *
     * @param storeName     Name of the storage that will be created (file path).
     * @param trace         Ref on project logger.
     * @throws Exception    If connection with the DB cannot be opened or if the DB cannot be created or if the JDBC driver cannot be loaded.
     */
    ActivityLogger(String storeName, MontoyaApi api, Trace trace) throws Exception {
        //Load the SQLite driver
        Class.forName("org.sqlite.JDBC");
        this.trace = trace;
        updateStoreLocation(storeName);
        startWriterThread();
    }

    /**
     * Start the background writer thread
     */
    private void startWriterThread() {
        writerThread = new Thread(this::processEventQueue, "ActivityLogger-Writer");
        writerThread.setDaemon(true);
        writerThread.start();
        this.trace.writeLog("Async writer thread started.");
    }

    /**
     * Background thread that processes the event queue
     */
    private void processEventQueue() {
        LogEvent[] batch = new LogEvent[BATCH_SIZE];
        
        while (running.get() || !eventQueue.isEmpty()) {
            try {
                int batchCount = 0;
                long batchStartTime = System.currentTimeMillis();
                
                // Collect events for batching
                while (batchCount < BATCH_SIZE && running.get()) {
                    LogEvent event = eventQueue.poll(BATCH_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                    if (event == null) {
                        break; // Timeout reached
                    }
                    batch[batchCount++] = event;
                    
                    // Check if we should flush early due to timeout
                    if (System.currentTimeMillis() - batchStartTime >= BATCH_TIMEOUT_MS) {
                        break;
                    }
                }
                
                // Process the batch if we have events
                if (batchCount > 0) {
                    writeBatch(batch, batchCount);
                }
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                this.trace.writeLog("Error in writer thread: " + e.getMessage());
            }
        }
        
        // Flush remaining events when shutting down
        flushRemainingEvents();
    }

    /**
     * Write a batch of events to the database
     */
    private void writeBatch(LogEvent[] batch, int count) throws Exception {
        ensureDBState();
        
        // Use batch inserts for better performance
        this.storageConnection.setAutoCommit(false);
        
        try (PreparedStatement stmt = this.storageConnection.prepareStatement(SQL_TABLE_INSERT)) {
            for (int i = 0; i < count; i++) {
                LogEvent event = batch[i];
                stmt.setString(1, event.localSourceIp);
                stmt.setString(2, event.targetUrl);
                stmt.setString(3, event.httpMethod);
                stmt.setString(4, event.tool);
                stmt.setString(5, event.requestRaw);
                stmt.setString(6, event.sendDateTime);
                stmt.setString(7, event.httpStatusCode);
                stmt.setString(8, event.responseRaw);
                stmt.addBatch();
            }
            
            int[] results = stmt.executeBatch();
            this.storageConnection.commit();
            
            // Log any failed inserts
            int successCount = 0;
            for (int result : results) {
                if (result > 0) successCount++;
            }
            
            if (successCount != count) {
                this.trace.writeLog("Batch insert: " + successCount + "/" + count + " events inserted successfully");
            }
            
        } catch (Exception e) {
            this.storageConnection.rollback();
            throw e;
        } finally {
            this.storageConnection.setAutoCommit(true);
        }
    }

    /**
     * Flush any remaining events in the queue (used during shutdown)
     */
    private void flushRemainingEvents() {
        LogEvent[] batch = new LogEvent[BATCH_SIZE];
        int count = 0;
        
        while (!eventQueue.isEmpty() && count < BATCH_SIZE) {
            LogEvent event = eventQueue.poll();
            if (event != null) {
                batch[count++] = event;
            }
        }
        
        if (count > 0) {
            try {
                writeBatch(batch, count);
                this.trace.writeLog("Flushed " + count + " remaining events during shutdown.");
            } catch (Exception e) {
                this.trace.writeLog("Error flushing remaining events: " + e.getMessage());
            }
        }
    }

    /**
     * Save an activity event into the storage (now async).
     *
     * @param request       HttpRequest object containing all information about the request
     *                      which was either sent or will be sent out soon.
     * @param response      HttpResponse object containing all information about the response.
     *                      Is null when only the request ist stored.
     * @param tool          The name of the tool which was used to issue to request.
     * @throws Exception    If event cannot be saved.
     */
    void logEvent(HttpRequest request, HttpResponse response, String tool) throws Exception {
        try {
            // Create event object with pre-computed values
            LogEvent event = new LogEvent(
                InetAddress.getLocalHost().getHostAddress(),
                request.url(),
                request.method(),
                tool,
                request.toString(),
                LocalDateTime.now().format(this.datetimeFormatter),
                response != null ? String.valueOf(response.statusCode()) : null,
                response != null ? response.bodyToString() : null
            );
            
            // Add to queue (non-blocking)
            if (!eventQueue.offer(event)) {
                // Queue is full - could log a warning or implement backpressure
                this.trace.writeLog("Event queue full, dropping event. Consider adjusting MAX_QUEUE_SIZE.");
            }
            
        } catch (Exception e) {
            this.trace.writeLog("Error queueing event: " + e.getMessage());
            // Could fallback to synchronous write in critical cases
        }
    }

    /**
     * Change the location where DB is stored.
     *
     * @param storeName Name of the storage that will be created (file path).
     * @throws Exception If connection with the DB cannot be opened or if the DB cannot be created or if the JDBC driver cannot be loaded.
     */
    void updateStoreLocation(String storeName) throws Exception {
        String newUrl = "jdbc:sqlite:" + storeName;
        this.url = newUrl;
        this.trace.writeLog("Activity information will be stored in database file '" + storeName + "'.");
        this.storageConnection = DriverManager.getConnection(newUrl);
        this.storageConnection.setAutoCommit(true);
        this.trace.writeLog("Open new connection to the storage.");
        try (Statement stmt = this.storageConnection.createStatement()) {
            stmt.execute(SQL_TABLE_CREATE);
            this.trace.writeLog("Recording table initialized.");
        }
    }

    /**
     * Extract and compute statistics about the DB.
     *
     * @return A VO object containing the statistics.
     * @throws Exception If computation meet and error.
     */
    DBStats getEventsStats() throws Exception {
        //Verify that the DB connection is still opened
        this.ensureDBState();
        //Get the total of the records in the activity table
        long recordsCount;
        try (PreparedStatement stmt = this.storageConnection.prepareStatement(SQL_COUNT_RECORDS)) {
            try (ResultSet rst = stmt.executeQuery()) {
                recordsCount = rst.getLong(1);
            }
        }
        //Get data amount if the DB is not empty
        long totalAmountDataSent = 0;
        long biggestRequestAmountDataSent = 0;
        long maxHitsBySecond = 0;
        if (recordsCount > 0) {
            //Get the total amount of data sent, we assume here that 1 character = 1 byte
            try (PreparedStatement stmt = this.storageConnection.prepareStatement(SQL_TOTAL_AMOUNT_DATA_SENT)) {
                try (ResultSet rst = stmt.executeQuery()) {
                    totalAmountDataSent = rst.getLong(1);
                }
            }
            //Get the amount of data sent by the biggest request, we assume here that 1 character = 1 byte
            try (PreparedStatement stmt = this.storageConnection.prepareStatement(SQL_BIGGEST_REQUEST_AMOUNT_DATA_SENT)) {
                try (ResultSet rst = stmt.executeQuery()) {
                    biggestRequestAmountDataSent = rst.getLong(1);
                }
            }
            //Get the maximum number of hits sent in a second
            try (PreparedStatement stmt = this.storageConnection.prepareStatement(SQL_MAX_HITS_BY_SECOND)) {
                try (ResultSet rst = stmt.executeQuery()) {
                    maxHitsBySecond = rst.getLong(1);
                }
            }
        }
        //Get the size of the file on the disk
        String fileLocation = this.url.replace("jdbc:sqlite:", "").trim();
        long fileSize = Paths.get(fileLocation).toFile().length();
        //Build the VO and return it
        return new DBStats(fileSize, recordsCount, totalAmountDataSent, biggestRequestAmountDataSent, maxHitsBySecond);
    }

    /**
     * Ensure the connection to the DB is valid.
     *
     * @throws Exception If connection cannot be verified or opened.
     */
    private void ensureDBState() throws Exception {
        //Verify that the DB connection is still opened
        if (this.storageConnection.isClosed()) {
            //Get new one
            this.trace.writeLog("Open new connection to the storage.");
            this.storageConnection = DriverManager.getConnection(url);
            this.storageConnection.setAutoCommit(true);
        }
    }

    /**
     * Unloads the extension by releasing the DB connection.
     */
    @Override
    public void extensionUnloaded() {
        // Signal the writer thread to stop
        running.set(false);
        
        // Wait for writer thread to finish processing
        if (writerThread != null) {
            try {
                writerThread.interrupt();
                writerThread.join(5000); // Wait up to 5 seconds
                this.trace.writeLog("Writer thread stopped.");
            } catch (InterruptedException e) {
                this.trace.writeLog("Interrupted while waiting for writer thread to finish.");
                Thread.currentThread().interrupt();
            }
        }
        
        // Close database connection
        try {
            if (this.storageConnection != null && !this.storageConnection.isClosed()) {
                this.storageConnection.close();
                this.trace.writeLog("Connection to the storage released.");
            }
        } catch (Exception e) {
            this.trace.writeLog("Cannot close the connection to the storage: " + e.getMessage());
        }
    }

    /**
     * Value object to hold event data for async processing
     */
    private static class LogEvent {
        final String localSourceIp;
        final String targetUrl;
        final String httpMethod;
        final String tool;
        final String requestRaw;
        final String sendDateTime;
        final String httpStatusCode;
        final String responseRaw;

        LogEvent(String localSourceIp, String targetUrl, String httpMethod, String tool,
                String requestRaw, String sendDateTime, String httpStatusCode, String responseRaw) {
            this.localSourceIp = localSourceIp;
            this.targetUrl = targetUrl;
            this.httpMethod = httpMethod;
            this.tool = tool;
            this.requestRaw = requestRaw;
            this.sendDateTime = sendDateTime;
            this.httpStatusCode = httpStatusCode;
            this.responseRaw = responseRaw;
        }
    }
}
