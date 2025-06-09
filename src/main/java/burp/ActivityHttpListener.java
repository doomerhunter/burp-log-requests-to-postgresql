package burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.handler.*;

import java.util.Locale;

/**
 * Handle the recording of HTTP activities into the activity log storage.
 */
class ActivityHttpListener implements HttpHandler {

    /**
     * Ref on handler that will store the activity information into the activity log storage.
     */
    private ActivityLogger activityLogger;

    /**
     * Ref on project logger.
     */
    private Trace trace;

    /**
     * Constructor.
     *
     * @param activityLogger    Ref on handler that will store the activity information into the activity log storage.
     * @param trace             Ref on project logger.
     */
    ActivityHttpListener(ActivityLogger activityLogger, Trace trace) {
        this.activityLogger = activityLogger;
        this.trace = trace;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent)
    {
        //Check if the response will be logged as well. If yes, wait until response is received.
        if (!ConfigMenu.INCLUDE_HTTP_RESPONSE_CONTENT) {
            try {
                String toolName = requestToBeSent.toolSource().toolType().toolName();
                if (this.mustLogRequest(requestToBeSent, toolName)) {
                    this.activityLogger.logEvent(requestToBeSent, null, toolName);
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
                    this.activityLogger.logEvent(responseReceived.initiatingRequest(), responseReceived, toolName);
                }
            } catch (Exception e) {
                this.trace.writeLog("Cannot save response: " + e.getMessage());
            }
        }
        return ResponseReceivedAction.continueWith(responseReceived);
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

        //Initially we check the pause state
        if (ConfigMenu.IS_LOGGING_PAUSED) {
            mustLogRequest = false;
        } else {
            //First: We check if we must apply restriction about tool source
            if (ConfigMenu.FILTER_BY_TOOL_SOURCE && !ConfigMenu.INCLUDED_TOOL_SOURCES.contains(toolName)) {
                mustLogRequest = false;
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
                    }
                }
            }
            //Finally: We check if we must apply restriction about the URL scope
            //Configuration restrictions options are applied in sequence so we only work here if the request is marked to be logged
            if (mustLogRequest && ConfigMenu.ONLY_INCLUDE_REQUESTS_FROM_SCOPE && ! request.isInScope()) {
                mustLogRequest = false;
            }
        }

        return mustLogRequest;

    }
}
