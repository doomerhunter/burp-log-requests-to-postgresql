package burp;

import java.net.InetAddress;
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
import java.util.List;
import java.util.stream.Collectors;
import java.util.Arrays;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.extension.ExtensionUnloadingHandler;

/**
 * Handle the recording of the activities into PostgreSQL database.
 * Uses async writes with a background thread for improved performance.
 */
class PostgreSQLActivityLogger implements ActivityStorage {

    /**
     * SQL instructions for PostgreSQL.
     */
    private static final String SQL_TABLE_CREATE = "CREATE TABLE IF NOT EXISTS ACTIVITY (" +
            "id SERIAL PRIMARY KEY, " +
            "local_source_ip TEXT, " +
            "target_url TEXT, " +
            "http_method TEXT, " +
            "burp_tool TEXT, " +
            "send_datetime TIMESTAMP, " +
            "request_raw TEXT, " +
            "request_headers TEXT, " +
            "request_body TEXT, " +
            "request_size INTEGER, " +
            "request_content_type TEXT, " +
            "response_raw TEXT, " +
            "response_headers TEXT, " +
            "response_body TEXT, " +
            "response_size INTEGER, " +
            "http_status_code INTEGER, " +
            "http_reason_phrase TEXT, " +
            "response_mime_type TEXT, " +
            "response_content_type TEXT, " +
            "http_version TEXT, " +
            "response_time_ms INTEGER, " +
            "request_raw_is_base64 BOOLEAN DEFAULT FALSE, " +
            "request_body_is_base64 BOOLEAN DEFAULT FALSE, " +
            "response_raw_is_base64 BOOLEAN DEFAULT FALSE, " +
            "response_body_is_base64 BOOLEAN DEFAULT FALSE, " +
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)";

    private static final String SQL_TABLE_INSERT = "INSERT INTO ACTIVITY " +
            "(local_source_ip, target_url, http_method, burp_tool, send_datetime, " +
            "request_raw, request_headers, request_body, request_size, request_content_type, " +
            "response_raw, response_headers, response_body, response_size, " +
            "http_status_code, http_reason_phrase, response_mime_type, response_content_type, " +
            "http_version, response_time_ms, request_raw_is_base64, request_body_is_base64, " +
            "response_raw_is_base64, response_body_is_base64) " +
            "VALUES(?,?,?,?,?::timestamp,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    private static final String SQL_COUNT_RECORDS = "SELECT COUNT(http_method) FROM ACTIVITY";
    private static final String SQL_TOTAL_AMOUNT_DATA_SENT = "SELECT SUM(request_size) FROM ACTIVITY WHERE request_size IS NOT NULL";
    private static final String SQL_BIGGEST_REQUEST_AMOUNT_DATA_SENT = "SELECT MAX(request_size) FROM ACTIVITY WHERE request_size IS NOT NULL";
    private static final String SQL_MAX_HITS_BY_SECOND = "SELECT COUNT(request_raw) AS hits, " +
            "DATE_TRUNC('second', send_datetime) as second_bucket " +
            "FROM ACTIVITY GROUP BY second_bucket ORDER BY hits DESC LIMIT 1";

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
     * Use a single DB connection for performance.
     */
    private Connection storageConnection;

    /**
     * Database connection parameters
     */
    private String host;
    private int port;
    private String database;
    private String username;
    private String password;

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
    private final BlockingQueue<EnhancedLogEvent> eventQueue = new LinkedBlockingQueue<>(MAX_QUEUE_SIZE);
    
    /**
     * Background thread for database writes
     */
    private Thread writerThread;
    
    /**
     * Flag to control the writer thread lifecycle
     */
    private final AtomicBoolean running = new AtomicBoolean(true);

    /**
     * UTF-8 validation and PostgreSQL safety utility methods
     */
    
    /**
     * Check if byte array contains valid UTF-8 sequences
     */
    private static boolean isValidUTF8(byte[] bytes) {
        int i = 0;
        while (i < bytes.length) {
            byte b = bytes[i];
            
            // ASCII (0xxxxxxx) - always valid
            if ((b & 0x80) == 0) {
                i++;
                continue;
            }
            
            // Multi-byte sequences
            int expectedBytes;
            if ((b & 0xE0) == 0xC0) expectedBytes = 2;      // 110xxxxx
            else if ((b & 0xF0) == 0xE0) expectedBytes = 3; // 1110xxxx  
            else if ((b & 0xF8) == 0xF0) expectedBytes = 4; // 11110xxx
            else return false; // Invalid start byte
            
            // Check we have enough bytes
            if (i + expectedBytes > bytes.length) return false;
            
            // Check continuation bytes (10xxxxxx)
            for (int j = 1; j < expectedBytes; j++) {
                if ((bytes[i + j] & 0xC0) != 0x80) return false;
            }
            
            i += expectedBytes;
        }
        return true;
    }
    
    /**
     * Check if string contains null bytes (PostgreSQL TEXT incompatible)
     */
    private static boolean containsNullBytes(String data) {
        return data != null && data.indexOf('\0') != -1;
    }
    
    /**
     * Check if byte array is safe for PostgreSQL TEXT columns
     */
    private static boolean isSafeForPostgreSQL(byte[] data) {
        if (data == null) return true;
        
        // Quick null byte check first (fastest rejection)
        for (byte b : data) {
            if (b == 0) return false;
        }
        
        // UTF-8 validation
        return isValidUTF8(data);
    }
    
    /**
     * Check if string is safe for PostgreSQL TEXT columns
     */
    private static boolean isSafeForPostgreSQL(String data) {
        if (data == null) return true;
        
        return !containsNullBytes(data) && 
               StandardCharsets.UTF_8.newEncoder().canEncode(data);
    }
    
    /**
     * Safe content wrapper with encoding information
     */
    private static class SafeContent {
        final String content;
        final boolean isBase64Encoded;
        
        SafeContent(String content, boolean isBase64Encoded) {
            this.content = content;
            this.isBase64Encoded = isBase64Encoded;
        }
    }
    
    /**
     * Make content safe for PostgreSQL by encoding binary data as Base64
     */
    private static SafeContent makeSafeForPostgreSQL(String data) {
        if (data == null) {
            return new SafeContent(null, false);
        }
        
        if (isSafeForPostgreSQL(data)) {
            return new SafeContent(data, false);
        }
        
        // Convert to Base64 for binary content
        try {
            byte[] bytes = data.getBytes(StandardCharsets.ISO_8859_1); // Preserve original bytes
            String base64Content = Base64.getEncoder().encodeToString(bytes);
            return new SafeContent(base64Content, true);
        } catch (Exception e) {
            // Fallback: sanitize by removing null bytes
            String sanitized = data.replace('\0', '?');
            return new SafeContent(sanitized, false);
        }
    }
    
    /**
     * Decode Base64 content back to original form
     * @param content The potentially Base64-encoded content
     * @param isBase64 Whether the content is Base64 encoded
     * @return The decoded content
     */
    public static String decodeContent(String content, boolean isBase64) {
        if (content == null || !isBase64) {
            return content;
        }
        
        try {
            byte[] decoded = Base64.getDecoder().decode(content);
            return new String(decoded, StandardCharsets.ISO_8859_1);
        } catch (Exception e) {
            // If decoding fails, return the original content
            return content;
        }
    }

    /**
     * Constructor.
     *
     * @param host          PostgreSQL host
     * @param port          PostgreSQL port
     * @param database      Database name
     * @param username      Database username
     * @param password      Database password
     * @param api           Montoya API reference
     * @param trace         Ref on project logger.
     * @throws Exception    If connection with the DB cannot be opened or if the DB cannot be created or if the JDBC driver cannot be loaded.
     */
    PostgreSQLActivityLogger(String host, int port, String database, String username, String password, MontoyaApi api, Trace trace) throws Exception {
        //Load the PostgreSQL driver
        Class.forName("org.postgresql.Driver");
        this.trace = trace;
        this.host = host;
        this.port = port;
        this.database = database;
        this.username = username;
        this.password = password;
        
        initializeConnection();
        startWriterThread();
    }

    /**
     * Initialize the database connection and create table if needed
     */
    private void initializeConnection() throws Exception {
        String url = String.format("jdbc:postgresql://%s:%d/%s", host, port, database);
        this.storageConnection = DriverManager.getConnection(url, username, password);
        this.storageConnection.setAutoCommit(true);
        this.trace.writeLog("Connected to PostgreSQL database at " + host + ":" + port + "/" + database);
        
        try (Statement stmt = this.storageConnection.createStatement()) {
            stmt.execute(SQL_TABLE_CREATE);
            this.trace.writeLog("PostgreSQL recording table initialized.");
        }
    }

    /**
     * Start the background writer thread
     */
    private void startWriterThread() {
        writerThread = new Thread(this::processEventQueue, "PostgreSQLActivityLogger-Writer");
        writerThread.setDaemon(true);
        writerThread.start();
        this.trace.writeLog("PostgreSQL async writer thread started.");
    }

    /**
     * Background thread that processes the event queue
     */
    private void processEventQueue() {
        EnhancedLogEvent[] batch = new EnhancedLogEvent[BATCH_SIZE];
        
        while (running.get() || !eventQueue.isEmpty()) {
            try {
                int batchCount = 0;
                long batchStartTime = System.currentTimeMillis();
                
                // Collect events for batching
                while (batchCount < BATCH_SIZE && running.get()) {
                    EnhancedLogEvent event = eventQueue.poll(BATCH_TIMEOUT_MS, TimeUnit.MILLISECONDS);
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
                this.trace.writeLog("Error in PostgreSQL writer thread: " + e.getMessage());
                // Try to reconnect if connection issues
                try {
                    if (this.storageConnection.isClosed()) {
                        initializeConnection();
                        this.trace.writeLog("Reconnected to PostgreSQL database.");
                    }
                } catch (Exception reconnectEx) {
                    this.trace.writeLog("Failed to reconnect to PostgreSQL: " + reconnectEx.getMessage());
                }
            }
        }
        
        // Flush remaining events when shutting down
        flushRemainingEvents();
    }

    /**
     * Write a batch of events to the database
     */
    private void writeBatch(EnhancedLogEvent[] batch, int count) throws Exception {
        ensureDBState();
        
        // Use batch inserts for better performance
        this.storageConnection.setAutoCommit(false);
        
        try (PreparedStatement stmt = this.storageConnection.prepareStatement(SQL_TABLE_INSERT)) {
            for (int i = 0; i < count; i++) {
                EnhancedLogEvent event = batch[i];
                stmt.setString(1, event.localSourceIp);
                stmt.setString(2, event.targetUrl);
                stmt.setString(3, event.httpMethod);
                stmt.setString(4, event.tool);
                stmt.setString(5, event.sendDateTime);
                stmt.setString(6, event.requestRaw);
                stmt.setString(7, event.requestHeaders);
                stmt.setString(8, event.requestBody);
                stmt.setObject(9, event.requestSize);
                stmt.setString(10, event.requestContentType);
                stmt.setString(11, event.responseRaw);
                stmt.setString(12, event.responseHeaders);
                stmt.setString(13, event.responseBody);
                stmt.setObject(14, event.responseSize);
                stmt.setObject(15, event.httpStatusCode);
                stmt.setString(16, event.httpReasonPhrase);
                stmt.setString(17, event.responseMimeType);
                stmt.setString(18, event.responseContentType);
                stmt.setString(19, event.httpVersion);
                stmt.setObject(20, event.responseTimeMs);
                stmt.setBoolean(21, event.requestRawIsBase64);
                stmt.setBoolean(22, event.requestBodyIsBase64);
                stmt.setBoolean(23, event.responseRawIsBase64);
                stmt.setBoolean(24, event.responseBodyIsBase64);
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
                this.trace.writeLog("PostgreSQL batch insert: " + successCount + "/" + count + " events inserted successfully");
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
        EnhancedLogEvent[] batch = new EnhancedLogEvent[BATCH_SIZE];
        int count = 0;
        
        while (!eventQueue.isEmpty() && count < BATCH_SIZE) {
            EnhancedLogEvent event = eventQueue.poll();
            if (event != null) {
                batch[count++] = event;
            }
        }
        
        if (count > 0) {
            try {
                writeBatch(batch, count);
                this.trace.writeLog("PostgreSQL flushed " + count + " remaining events during shutdown.");
            } catch (Exception e) {
                this.trace.writeLog("Error flushing remaining PostgreSQL events: " + e.getMessage());
            }
        }
    }

    /**
     * Save an activity event into the storage (legacy method for backward compatibility).
     */
    public void logEvent(HttpRequest request, HttpResponse response, String tool) throws Exception {
        logEventEnhanced(request, response, tool, 0);
    }

    /**
     * Save an activity event into the storage with enhanced details.
     */
    public void logEventEnhanced(HttpRequest request, HttpResponse response, String tool, long requestStartTime) throws Exception {
        try {
            // Calculate response time if we have a start time and response
            Long responseTimeMs = null;
            if (requestStartTime > 0 && response != null) {
                responseTimeMs = System.currentTimeMillis() - requestStartTime;
            }

            // Extract request details with safety checks
            String requestHeaders = extractHeaders(request.headers());
            SafeContent safeRequestRaw = makeSafeForPostgreSQL(request.toString());
            SafeContent safeRequestBody = makeSafeForPostgreSQL(request.body() != null ? request.bodyToString() : null);
            Integer requestSize = request.toByteArray() != null ? request.toByteArray().length() : null;
            String requestContentType = request.headerValue("Content-Type");

            // Extract response details with safety checks
            String responseHeaders = null;
            SafeContent safeResponseRaw = new SafeContent(null, false);
            SafeContent safeResponseBody = new SafeContent(null, false);
            Integer responseSize = null;
            Integer httpStatusCode = null;
            String httpReasonPhrase = null;
            String responseMimeType = null;
            String responseContentType = null;

            if (response != null) {
                safeResponseRaw = makeSafeForPostgreSQL(response.toString());
                responseHeaders = extractHeaders(response.headers());
                safeResponseBody = makeSafeForPostgreSQL(response.bodyToString());
                responseSize = response.toByteArray() != null ? response.toByteArray().length() : null;
                httpStatusCode = (int) response.statusCode();
                httpReasonPhrase = response.reasonPhrase();
                if (response.mimeType() != null) {
                    responseMimeType = response.mimeType().toString();
                }
                responseContentType = response.headerValue("Content-Type");
            }

            // Create enhanced event object
            EnhancedLogEvent event = new EnhancedLogEvent(
                InetAddress.getLocalHost().getHostAddress(),
                request.url(),
                request.method(),
                tool,
                LocalDateTime.now().format(this.datetimeFormatter),
                safeRequestRaw.content,
                requestHeaders,
                safeRequestBody.content,
                requestSize,
                requestContentType,
                safeResponseRaw.content,
                responseHeaders,
                safeResponseBody.content,
                responseSize,
                httpStatusCode,
                httpReasonPhrase,
                responseMimeType,
                responseContentType,
                request.httpVersion(),
                responseTimeMs,
                safeRequestRaw.isBase64Encoded,
                safeRequestBody.isBase64Encoded,
                safeResponseRaw.isBase64Encoded,
                safeResponseBody.isBase64Encoded
            );
            
            // Log if any content was Base64 encoded
            if (safeRequestRaw.isBase64Encoded || safeRequestBody.isBase64Encoded || 
                safeResponseRaw.isBase64Encoded || safeResponseBody.isBase64Encoded) {
                this.trace.writeLog("PostgreSQL: Binary content detected and Base64 encoded for " + 
                                  request.method() + " " + request.url() + 
                                  " (req_raw=" + safeRequestRaw.isBase64Encoded + 
                                  ", req_body=" + safeRequestBody.isBase64Encoded + 
                                  ", resp_raw=" + safeResponseRaw.isBase64Encoded + 
                                  ", resp_body=" + safeResponseBody.isBase64Encoded + ")");
            }
            
            // Add to queue (non-blocking)
            if (!eventQueue.offer(event)) {
                // Queue is full - could log a warning or implement backpressure
                this.trace.writeLog("PostgreSQL event queue full, dropping event. Consider adjusting MAX_QUEUE_SIZE.");
            }
            
        } catch (Exception e) {
            this.trace.writeLog("Error queueing enhanced PostgreSQL event: " + e.getMessage());
            // Could fallback to synchronous write in critical cases
        }
    }

    /**
     * Extract headers as a JSON-like string representation
     */
    private String extractHeaders(List<HttpHeader> headers) {
        if (headers == null || headers.isEmpty()) {
            return null;
        }
        
        return headers.stream()
            .map(header -> "\"" + escapeJson(header.name()) + "\": \"" + escapeJson(header.value()) + "\"")
            .collect(Collectors.joining(", ", "{", "}"));
    }

    /**
     * Simple JSON string escaping
     */
    private String escapeJson(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r")
                   .replace("\t", "\\t");
    }

    /**
     * Update database connection parameters and reconnect.
     *
     * @param host          PostgreSQL host
     * @param port          PostgreSQL port
     * @param database      Database name
     * @param username      Database username
     * @param password      Database password
     * @throws Exception    If connection with the DB cannot be opened or if the DB cannot be created.
     */
    void updateConnectionParameters(String host, int port, String database, String username, String password) throws Exception {
        this.host = host;
        this.port = port;
        this.database = database;
        this.username = username;
        this.password = password;
        
        // Close existing connection
        if (this.storageConnection != null && !this.storageConnection.isClosed()) {
            this.storageConnection.close();
        }
        
        // Create new connection
        initializeConnection();
        this.trace.writeLog("PostgreSQL connection parameters updated and reconnected.");
    }

    /**
     * Extract and compute statistics about the DB.
     *
     * @return A VO object containing the statistics.
     * @throws Exception If computation meets an error.
     */
    public DBStats getEventsStats() throws Exception {
        //Verify that the DB connection is still opened
        this.ensureDBState();
        
        //Get the total of the records in the activity table
        long recordsCount;
        try (PreparedStatement stmt = this.storageConnection.prepareStatement(SQL_COUNT_RECORDS)) {
            try (ResultSet rst = stmt.executeQuery()) {
                recordsCount = rst.next() ? rst.getLong(1) : 0;
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
                    if (rst.next()) {
                        totalAmountDataSent = rst.getLong(1);
                    }
                }
            }
            
            //Get the amount of data sent by the biggest request, we assume here that 1 character = 1 byte
            try (PreparedStatement stmt = this.storageConnection.prepareStatement(SQL_BIGGEST_REQUEST_AMOUNT_DATA_SENT)) {
                try (ResultSet rst = stmt.executeQuery()) {
                    if (rst.next()) {
                        biggestRequestAmountDataSent = rst.getLong(1);
                    }
                }
            }
            
            //Get the maximum number of hits sent in a second
            try (PreparedStatement stmt = this.storageConnection.prepareStatement(SQL_MAX_HITS_BY_SECOND)) {
                try (ResultSet rst = stmt.executeQuery()) {
                    if (rst.next()) {
                        maxHitsBySecond = rst.getLong(1);
                    }
                }
            }
        }
        
        //For PostgreSQL, we'll estimate DB size based on table statistics
        //This is an approximation since PostgreSQL doesn't have a simple file size equivalent
        long estimatedSize = recordsCount * 1024; // Rough estimate
        
        //Build the VO and return it
        return new DBStats(estimatedSize, recordsCount, totalAmountDataSent, biggestRequestAmountDataSent, maxHitsBySecond);
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
            this.trace.writeLog("PostgreSQL connection lost, reconnecting...");
            initializeConnection();
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
                this.trace.writeLog("PostgreSQL writer thread stopped.");
            } catch (InterruptedException e) {
                this.trace.writeLog("Interrupted while waiting for PostgreSQL writer thread to finish.");
                Thread.currentThread().interrupt();
            }
        }
        
        // Close database connection
        try {
            if (this.storageConnection != null && !this.storageConnection.isClosed()) {
                this.storageConnection.close();
                this.trace.writeLog("PostgreSQL connection released.");
            }
        } catch (Exception e) {
            this.trace.writeLog("Cannot close the PostgreSQL connection: " + e.getMessage());
        }
    }

    /**
     * Enhanced value object to hold event data for async processing
     */
    private static class EnhancedLogEvent {
        final String localSourceIp;
        final String targetUrl;
        final String httpMethod;
        final String tool;
        final String sendDateTime;
        final String requestRaw;
        final String requestHeaders;
        final String requestBody;
        final Integer requestSize;
        final String requestContentType;
        final String responseRaw;
        final String responseHeaders;
        final String responseBody;
        final Integer responseSize;
        final Integer httpStatusCode;
        final String httpReasonPhrase;
        final String responseMimeType;
        final String responseContentType;
        final String httpVersion;
        final Long responseTimeMs;
        final boolean requestRawIsBase64;
        final boolean requestBodyIsBase64;
        final boolean responseRawIsBase64;
        final boolean responseBodyIsBase64;

        EnhancedLogEvent(String localSourceIp, String targetUrl, String httpMethod, String tool,
                String sendDateTime, String requestRaw, String requestHeaders, String requestBody,
                Integer requestSize, String requestContentType, String responseRaw, String responseHeaders,
                String responseBody, Integer responseSize, Integer httpStatusCode, String httpReasonPhrase,
                String responseMimeType, String responseContentType, String httpVersion, Long responseTimeMs,
                boolean requestRawIsBase64, boolean requestBodyIsBase64, boolean responseRawIsBase64, 
                boolean responseBodyIsBase64) {
            this.localSourceIp = localSourceIp;
            this.targetUrl = targetUrl;
            this.httpMethod = httpMethod;
            this.tool = tool;
            this.sendDateTime = sendDateTime;
            this.requestRaw = requestRaw;
            this.requestHeaders = requestHeaders;
            this.requestBody = requestBody;
            this.requestSize = requestSize;
            this.requestContentType = requestContentType;
            this.responseRaw = responseRaw;
            this.responseHeaders = responseHeaders;
            this.responseBody = responseBody;
            this.responseSize = responseSize;
            this.httpStatusCode = httpStatusCode;
            this.httpReasonPhrase = httpReasonPhrase;
            this.responseMimeType = responseMimeType;
            this.responseContentType = responseContentType;
            this.httpVersion = httpVersion;
            this.responseTimeMs = responseTimeMs;
            this.requestRawIsBase64 = requestRawIsBase64;
            this.requestBodyIsBase64 = requestBodyIsBase64;
            this.responseRawIsBase64 = responseRawIsBase64;
            this.responseBodyIsBase64 = responseBodyIsBase64;
        }
    }
} 