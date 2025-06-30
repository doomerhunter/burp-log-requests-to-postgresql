package burp;

import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;


/**
 * Entry point of the extension
 */
public class BurpExtender implements BurpExtension {

    /**
     * The MontoyaAPI object used for accessing all the Burp features and resources such as requests and responses.
     */
    private MontoyaApi api;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        Preferences preferences = this.api.persistence().preferences();
        ConfigMenu configMenu = null;
        String extensionName = "LogRequestsToPostgreSQL";
        JFrame burpFrame = ConfigMenu.getBurpFrame();

        try {
            //Extension init.
            this.api.extension().setName(extensionName);
            Trace trace = new Trace(this.api);
            
            Boolean isLoggingPaused = Boolean.TRUE.equals(preferences.getBoolean(ConfigMenu.PAUSE_LOGGING_CFG_KEY));
            
            ActivityStorage activityStorage = null;
            ActivityHttpListener activityHttpListener = null;
            
            if (!isLoggingPaused) {
                // Check if PostgreSQL is configured
                String pgHost = preferences.getString(ConfigMenu.POSTGRESQL_HOST_CFG_KEY);
                String pgDb = preferences.getString(ConfigMenu.POSTGRESQL_DATABASE_CFG_KEY);
                
                String msg;
                Object[] options;
                
                if (pgHost == null || pgHost.trim().isEmpty() || pgDb == null || pgDb.trim().isEmpty()) {
                    // PostgreSQL not configured, ask user to configure
                    msg = "PostgreSQL storage is not configured. Would you like to configure it now?";
                    options = new Object[]{"Configure PostgreSQL", "Pause the logging"};
                } else {
                    msg = "Continue to log events into PostgreSQL database?\n\rHost: " + pgHost + "\n\rDatabase: " + pgDb;
                    options = new Object[]{"Continue", "Reconfigure PostgreSQL", "Pause the logging"};
                }
                
                //Mapping of the buttons with the dialog: options[0] => YES / options[1] => NO / options[2] => CANCEL (if 3 options)
                int loggingQuestionReply = JOptionPane.showOptionDialog(burpFrame, msg, extensionName, 
                    JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, null);
                
                //Case for YES (Continue/Configure PostgreSQL)
                if (loggingQuestionReply == JOptionPane.YES_OPTION) {
                    if (pgHost == null || pgHost.trim().isEmpty() || pgDb == null || pgDb.trim().isEmpty()) {
                        // Configure PostgreSQL
                        if (ActivityStorageFactory.showPostgreSQLConfigDialog(preferences, burpFrame)) {
                            preferences.setBoolean(ConfigMenu.PAUSE_LOGGING_CFG_KEY, Boolean.FALSE);
                            this.api.logging().logToOutput("PostgreSQL storage configured and logging is enabled.");
                        } else {
                            preferences.setBoolean(ConfigMenu.PAUSE_LOGGING_CFG_KEY, Boolean.TRUE);
                            this.api.logging().logToOutput("PostgreSQL configuration cancelled. Logging is paused.");
                        }
                    } else {
                        preferences.setBoolean(ConfigMenu.PAUSE_LOGGING_CFG_KEY, Boolean.FALSE);
                        this.api.logging().logToOutput("PostgreSQL logging is enabled.");
                    }
                }
                //Case for NO (Reconfigure PostgreSQL or Pause if only 2 options)
                else if (loggingQuestionReply == JOptionPane.NO_OPTION) {
                    if (options.length == 3) {
                        // Reconfigure PostgreSQL
                        if (ActivityStorageFactory.showPostgreSQLConfigDialog(preferences, burpFrame)) {
                            preferences.setBoolean(ConfigMenu.PAUSE_LOGGING_CFG_KEY, Boolean.FALSE);
                            this.api.logging().logToOutput("PostgreSQL storage reconfigured and logging is enabled.");
                        } else {
                            preferences.setBoolean(ConfigMenu.PAUSE_LOGGING_CFG_KEY, Boolean.FALSE);
                            this.api.logging().logToOutput("PostgreSQL configuration unchanged. Logging is enabled.");
                        }
                    } else {
                        // Pause the logging (when only 2 options)
                        preferences.setBoolean(ConfigMenu.PAUSE_LOGGING_CFG_KEY, Boolean.TRUE);
                        this.api.logging().logToOutput("Logging is paused.");
                    }
                }
                //Case for CANCEL => Pause the logging (when 3 options)
                else if (loggingQuestionReply == JOptionPane.CANCEL_OPTION) {
                    preferences.setBoolean(ConfigMenu.PAUSE_LOGGING_CFG_KEY, Boolean.TRUE);
                    this.api.logging().logToOutput("Logging is paused.");
                }
            } else {
                this.api.logging().logToOutput("Logging is paused.");
            }
            
            // Try to create storage, but handle connection failures gracefully
            try {
                activityStorage = ActivityStorageFactory.createStorage(preferences, this.api, trace);
                activityHttpListener = new ActivityHttpListener(activityStorage, trace);
            } catch (Exception e) {
                String errMsg = "Cannot connect to PostgreSQL database: " + e.getMessage() + "\n\rLogging will be paused. You can reconfigure the connection later.";
                this.api.logging().raiseErrorEvent(errMsg);
                JOptionPane.showMessageDialog(burpFrame, errMsg, extensionName, JOptionPane.WARNING_MESSAGE);
                
                // Pause logging and create a dummy storage
                preferences.setBoolean(ConfigMenu.PAUSE_LOGGING_CFG_KEY, Boolean.TRUE);
                // Create a dummy storage that does nothing
                activityStorage = new DummyActivityStorage();
                activityHttpListener = new ActivityHttpListener(activityStorage, trace);
            }
            
            //Setup the configuration menu
            configMenu = new ConfigMenu(this.api, trace, activityStorage, activityHttpListener);
            SwingUtilities.invokeLater(configMenu);
            //Register all listeners
            this.api.http().registerHttpHandler(activityHttpListener);
            this.api.extension().registerUnloadingHandler(activityStorage);
        } catch (Exception e) {
            String errMsg = "Cannot start the extension due to the following reason:\n\r" + e.getMessage();
            //Notification of the error in the dashboard tab
            this.api.logging().raiseErrorEvent(errMsg);
            //Notification of the error using the UI
            JOptionPane.showMessageDialog(burpFrame, errMsg, extensionName, JOptionPane.ERROR_MESSAGE);
        }
    }

    // Add a dummy storage class for when connection fails
    private static class DummyActivityStorage implements ActivityStorage {
        @Override
        public void logEvent(HttpRequest request, HttpResponse response, String tool) throws Exception {
            // Do nothing - logging is paused
        }
        
        @Override
        public void logEventEnhanced(HttpRequest request, HttpResponse response, String tool, long requestStartTime) throws Exception {
            // Do nothing - logging is paused
        }
        
        @Override
        public DBStats getEventsStats() throws Exception {
            // Return empty stats since no data is being logged
            return new DBStats(0, 0, 0, 0, 0);
        }
        
        @Override
        public void extensionUnloaded() {
            // Do nothing
        }
    }
}
