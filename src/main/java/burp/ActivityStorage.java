package burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.extension.ExtensionUnloadingHandler;

/**
 * Interface for activity storage implementations.
 * This allows for different storage backends (SQLite, PostgreSQL, etc.)
 * while maintaining a consistent API.
 */
interface ActivityStorage extends ExtensionUnloadingHandler {

    /**
     * Save an activity event into the storage.
     *
     * @param request       HttpRequest object containing all information about the request
     *                      which was either sent or will be sent out soon.
     * @param response      HttpResponse object containing all information about the response.
     *                      Is null when only the request is stored.
     * @param tool          The name of the tool which was used to issue the request.
     * @throws Exception    If event cannot be saved.
     */
    void logEvent(HttpRequest request, HttpResponse response, String tool) throws Exception;

    /**
     * Save an activity event into the storage with enhanced details.
     * This method provides additional metadata for comprehensive logging.
     *
     * @param request           HttpRequest object containing all information about the request
     * @param response          HttpResponse object containing all information about the response
     * @param tool              The name of the tool which was used to issue the request
     * @param requestStartTime  Timestamp when request was sent (for response time calculation)
     * @throws Exception        If event cannot be saved.
     */
    default void logEventEnhanced(HttpRequest request, HttpResponse response, String tool, long requestStartTime) throws Exception {
        // Default implementation falls back to basic logEvent for backward compatibility
        logEvent(request, response, tool);
    }

    /**
     * Extract and compute statistics about the storage.
     *
     * @return A VO object containing the statistics.
     * @throws Exception If computation meets an error.
     */
    DBStats getEventsStats() throws Exception;
} 