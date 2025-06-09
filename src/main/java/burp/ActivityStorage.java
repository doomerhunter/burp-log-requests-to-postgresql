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
     * Extract and compute statistics about the storage.
     *
     * @return A VO object containing the statistics.
     * @throws Exception If computation meets an error.
     */
    DBStats getEventsStats() throws Exception;
} 