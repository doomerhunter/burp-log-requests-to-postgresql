package burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.handler.*;

import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Handle the recording of HTTP activities into the activity log storage.
 */
class ActivityHttpListener implements HttpHandler {

    /**
     * Ref on handler that will store the activity information into the activity log storage.
     */
    private ActivityStorage activityStorage;

    /**
     * Ref on project logger.
     */
    private Trace trace;

    /**
     * Map to track request start times for response time calculation.
     * Uses request hash as key to avoid memory leaks with request objects.
     */
    private final ConcurrentHashMap<Integer, Long> requestStartTimes = new ConcurrentHashMap<>();

    /**
     * Constructor.
     *
     * @param activityStorage   Ref on handler that will store the activity information into the activity log storage.
     * @param trace             Ref on project logger.
     */
    ActivityHttpListener(ActivityStorage activityStorage, Trace trace) {
        this.activityStorage = activityStorage;
        this.trace = trace;
    }

    /**
     * Replace the current activity storage with a new one.
     * This allows switching between storage backends without restarting Burp Suite.
     *
     * @param newStorage The new storage instance to use
     */
    void replaceStorage(ActivityStorage newStorage) {
        this.activityStorage = newStorage;
        this.trace.writeLog("HTTP listener activity storage replaced.");
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent)
    {
        String toolName = requestToBeSent.toolSource().toolType().toolName();
        
        // Always track request start time for response time calculation
        if (ConfigMenu.INCLUDE_HTTP_RESPONSE_CONTENT && this.mustLogRequest(requestToBeSent, toolName)) {
            int requestHash = generateRequestHash(requestToBeSent);
            requestStartTimes.put(requestHash, System.currentTimeMillis());
        }
        
        //Check if the response will be logged as well. If yes, wait until response is received.
        if (!ConfigMenu.INCLUDE_HTTP_RESPONSE_CONTENT) {
            try {
                if (this.mustLogRequest(requestToBeSent, toolName)) {
                    // Use enhanced logging even for request-only scenarios
                    this.activityStorage.logEventEnhanced(requestToBeSent, null, toolName, 0);
                }
            } catch (Exception e) {
                this.trace.writeLog("Cannot save request: " + e.getMessage());
            }
        }
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived)
    {
        if (ConfigMenu.INCLUDE_HTTP_RESPONSE_CONTENT) {
            try {
                //Save the information of the current request if the message is an HTTP response and according to the restriction options
                String toolName = responseReceived.toolSource().toolType().toolName();
                if (this.mustLogRequest(responseReceived.initiatingRequest(), toolName)) {
                    // Get request start time for response time calculation
                    int requestHash = generateRequestHash(responseReceived.initiatingRequest());
                    Long startTime = requestStartTimes.remove(requestHash);
                    long requestStartTime = startTime != null ? startTime : 0;
                    
                    // Use enhanced logging with timing information
                    this.activityStorage.logEventEnhanced(responseReceived.initiatingRequest(), responseReceived, toolName, requestStartTime);
                }
            } catch (Exception e) {
                this.trace.writeLog("Cannot save response: " + e.getMessage());
            }
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    /**
     * Generate a hash for request tracking that doesn't hold references to the request object.
     * This prevents memory leaks while allowing us to correlate requests with responses.
     */
    private int generateRequestHash(HttpRequest request) {
        // Generate hash based on URL, method, and a portion of headers/body
        // This should be unique enough for correlation but not hold object references
        String hashSource = request.url() + "|" + request.method() + "|" + 
                           (request.body() != null ? request.body().hashCode() : 0);
        return hashSource.hashCode();
    }

    /**
     * Determine if the current request must be logged according to the configuration options selected by the users.
     *
     * @param request HttpRequest object containing all the information about the request
     * @param toolName Name of the tool that generated this request (e.g., "Repeater", "Intruder", "Proxy")
     * @return TRUE if the request must be logged, FALSE otherwise
     */
    private boolean mustLogRequest(HttpRequest request, String toolName) {
        //By default: Request is logged
        boolean mustLogRequest = true;
        String url = request.url();

        //this.trace.writeLog("DEBUG: Checking request from " + toolName + " to " + url);

        //Initially we check the pause state
        if (ConfigMenu.IS_LOGGING_PAUSED) {
            mustLogRequest = false;
            //this.trace.writeLog("DEBUG: Request filtered out - logging is paused");
        } else {
            //First: We check if we must apply restriction about tool source
            if (ConfigMenu.FILTER_BY_TOOL_SOURCE) {
                // Debug logging to see actual tool names
                //this.trace.writeLog("Received tool name: '" + toolName + "', Included tools: " + ConfigMenu.INCLUDED_TOOL_SOURCES.toString());
                
                // Check if any of the included tool sources match (case-insensitive)
                boolean toolMatches = ConfigMenu.INCLUDED_TOOL_SOURCES.stream()
                    .anyMatch(includedTool -> includedTool.equalsIgnoreCase(toolName));
                
                if (!toolMatches) {
                    mustLogRequest = false;
                    //this.trace.writeLog("DEBUG: Request from tool '" + toolName + "' filtered out by tool source filter.");
                } else {
                    //this.trace.writeLog("DEBUG: Tool '" + toolName + "' passed tool source filter.");
                }
            }
            //Second: We check if we must apply restriction about image resource
            //Configuration restrictions options are applied in sequence so we only work here if the request is marked to be logged
            if (mustLogRequest && ConfigMenu.EXCLUDE_IMAGE_RESOURCE_REQUESTS) {
                //Get the file extension of the current URL and remove the parameters from the URL
                String filename = request.url();
                if (filename != null && filename.indexOf('?') != -1) {
                    filename = filename.substring(0, filename.indexOf('?')).trim();
                }
                if (filename != null && filename.indexOf('#') != -1) {
                    filename = filename.substring(0, filename.indexOf('#')).trim();
                }
                if (filename != null && filename.lastIndexOf('.') != -1) {
                    String extension = filename.substring(filename.lastIndexOf('.') + 1).trim().toLowerCase(Locale.US);
                    if (ConfigMenu.IMAGE_RESOURCE_EXTENSIONS.contains(extension)) {
                        mustLogRequest = false;
                        //this.trace.writeLog("DEBUG: Request filtered out - image resource with extension: " + extension);
                    }
                }
            }
            //Finally: We check if we must apply restriction about the URL scope
            //Configuration restrictions options are applied in sequence so we only work here if the request is marked to be logged
            if (mustLogRequest && ConfigMenu.ONLY_INCLUDE_REQUESTS_FROM_SCOPE && ! request.isInScope()) {
                mustLogRequest = false;
                //this.trace.writeLog("DEBUG: Request filtered out - not in scope: " + url);
            }
        }

        //this.trace.writeLog("DEBUG: Final decision for " + toolName + " request to " + url + ": " + (mustLogRequest ? "LOGGED" : "FILTERED"));
        return mustLogRequest;

    }
}
