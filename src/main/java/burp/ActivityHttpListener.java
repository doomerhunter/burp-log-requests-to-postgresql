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
    private ActivityStorage activityStorage;

    /**
     * Ref on project logger.
     */
    private Trace trace;

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
        //Check if the response will be logged as well. If yes, wait until response is received.
        if (!ConfigMenu.INCLUDE_HTTP_RESPONSE_CONTENT) {
            try {
                if (this.mustLogRequest(requestToBeSent)) {
                    this.activityStorage.logEvent(requestToBeSent, null, requestToBeSent.toolSource().toolType().toolName());
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
                if (this.mustLogRequest(responseReceived.initiatingRequest())) {
                    this.activityStorage.logEvent(responseReceived.initiatingRequest(), responseReceived, responseReceived.toolSource().toolType().toolName());
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
     * @return TRUE if the request must be logged, FALSE otherwise
     */
    private boolean mustLogRequest(HttpRequest request) {
        //By default: Request is logged
        boolean mustLogRequest = true;

        //Initially we check the pause state
        if (ConfigMenu.IS_LOGGING_PAUSED) {
            mustLogRequest = false;
        } else {
            //First: We check if we must apply restriction about image resource
            if (ConfigMenu.EXCLUDE_IMAGE_RESOURCE_REQUESTS) {
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
            //Secondly: We check if we must apply restriction about the URL scope
            //Configuration restrictions options are applied in sequence so we only work here if the request is marked to be logged
            if (mustLogRequest && ConfigMenu.ONLY_INCLUDE_REQUESTS_FROM_SCOPE && ! request.isInScope()) {
                mustLogRequest = false;
            }
        }

        return mustLogRequest;

    }
}
