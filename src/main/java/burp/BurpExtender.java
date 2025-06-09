package burp;

import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;


/**
 * Entry point of the extension
 */
public class BurpExtender implements BurpExtension {

    /**
     * The MontoyaAPI object used for accessing all the Burp features and ressources such as requests and responses.
     */
    private MontoyaApi api;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        Preferences preferences = this.api.persistence().preferences();
        ConfigMenu configMenu = null;
        String extensionName = "LogRequestsToSQLite";
        JFrame burpFrame = ConfigMenu.getBurpFrame();

        try {
            //Extension init.
            this.api.extension().setName(extensionName);
            Trace trace = new Trace(this.api);
            //If the logging is not paused then ask to the user if he want to continue to log the events in the current DB file or pause the logging
            String defaultStoreFileName = new File(System.getProperty("user.home"), extensionName + ".db").getAbsolutePath().replaceAll("\\\\", "/");
            String customStoreFileName = preferences.getString(ConfigMenu.DB_FILE_CUSTOM_LOCATION_CFG_KEY);
            if (customStoreFileName == null || !Files.exists(Paths.get(customStoreFileName))) {
                if(customStoreFileName != null){
                    this.api.logging().logToOutput("Default store file used because the previously stored DB file do not exist anymore ('" + customStoreFileName + "')");
                }
                customStoreFileName = defaultStoreFileName;
            }
            Boolean isLoggingPaused = Boolean.TRUE.equals(preferences.getBoolean(ConfigMenu.PAUSE_LOGGING_CFG_KEY));
            Boolean usePostgreSQL = Boolean.TRUE.equals(preferences.getBoolean(ConfigMenu.USE_POSTGRESQL_CFG_KEY));
            
            if (!isLoggingPaused) {
                String msg;
                Object[] options;
                
                if (usePostgreSQL) {
                    // Check if PostgreSQL is configured
                    String pgHost = preferences.getString(ConfigMenu.POSTGRESQL_HOST_CFG_KEY);
                    String pgDb = preferences.getString(ConfigMenu.POSTGRESQL_DATABASE_CFG_KEY);
                    if (pgHost == null || pgHost.trim().isEmpty() || pgDb == null || pgDb.trim().isEmpty()) {
                        // PostgreSQL not configured, ask user to configure
                        msg = "PostgreSQL storage is enabled but not configured. Would you like to configure it now?";
                        options = new Object[]{"Configure PostgreSQL", "Use SQLite instead", "Pause the logging"};
                    } else {
                        msg = "Continue to log events into PostgreSQL database?\n\rHost: " + pgHost + "\n\rDatabase: " + pgDb;
                        options = new Object[]{"Continue", "Reconfigure PostgreSQL", "Pause the logging"};
                    }
                } else {
                    msg = "Continue to log events into the following SQLite database file?\n\r" + customStoreFileName;
                    options = new Object[]{"Keep the DB file", "Change the DB file", "Pause the logging"};
                }
                //Mapping of the buttons with the dialog: options[0] => YES / options[1] => NO / options[2] => CANCEL
                int loggingQuestionReply = JOptionPane.showOptionDialog(burpFrame, msg, extensionName, JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, null);
                
                if (usePostgreSQL) {
                    //Case for YES (Continue/Configure PostgreSQL)
                    if (loggingQuestionReply == JOptionPane.YES_OPTION) {
                        String pgHost = preferences.getString(ConfigMenu.POSTGRESQL_HOST_CFG_KEY);
                        String pgDb = preferences.getString(ConfigMenu.POSTGRESQL_DATABASE_CFG_KEY);
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
                    //Case for NO (Use SQLite instead/Reconfigure PostgreSQL)
                    if (loggingQuestionReply == JOptionPane.NO_OPTION) {
                        String pgHost = preferences.getString(ConfigMenu.POSTGRESQL_HOST_CFG_KEY);
                        String pgDb = preferences.getString(ConfigMenu.POSTGRESQL_DATABASE_CFG_KEY);
                        if (pgHost == null || pgHost.trim().isEmpty() || pgDb == null || pgDb.trim().isEmpty()) {
                            // Use SQLite instead
                            preferences.setBoolean(ConfigMenu.USE_POSTGRESQL_CFG_KEY, Boolean.FALSE);
                            preferences.setBoolean(ConfigMenu.PAUSE_LOGGING_CFG_KEY, Boolean.FALSE);
                            this.api.logging().logToOutput("Switched to SQLite storage and logging is enabled.");
                        } else {
                            // Reconfigure PostgreSQL
                            if (ActivityStorageFactory.showPostgreSQLConfigDialog(preferences, burpFrame)) {
                                preferences.setBoolean(ConfigMenu.PAUSE_LOGGING_CFG_KEY, Boolean.FALSE);
                                this.api.logging().logToOutput("PostgreSQL storage reconfigured and logging is enabled.");
                            } else {
                                preferences.setBoolean(ConfigMenu.PAUSE_LOGGING_CFG_KEY, Boolean.FALSE);
                                this.api.logging().logToOutput("PostgreSQL configuration unchanged. Logging is enabled.");
                            }
                        }
                    }
                    //Case for CANCEL => Pause the logging
                    if (loggingQuestionReply == JOptionPane.CANCEL_OPTION) {
                        preferences.setBoolean(ConfigMenu.PAUSE_LOGGING_CFG_KEY, Boolean.TRUE);
                        this.api.logging().logToOutput("Logging is paused.");
                    }
                } else {
                    //SQLite mode
                    //Case for YES is already handled, use the stored file
                    if (loggingQuestionReply == JOptionPane.YES_OPTION) {
                        preferences.setBoolean(ConfigMenu.PAUSE_LOGGING_CFG_KEY, Boolean.FALSE);
                        this.api.logging().logToOutput("SQLite logging is enabled.");
                    }
                    //Case for the NO => Change DB file
                    if (loggingQuestionReply == JOptionPane.NO_OPTION) {
                        JFileChooser customStoreFileNameFileChooser = Utilities.createDBFileChooser();
                        int dbFileSelectionReply = customStoreFileNameFileChooser.showDialog(burpFrame, "Use");
                        if (dbFileSelectionReply == JFileChooser.APPROVE_OPTION) {
                            customStoreFileName = customStoreFileNameFileChooser.getSelectedFile().getAbsolutePath().replaceAll("\\\\", "/");
                        } else {
                            JOptionPane.showMessageDialog(burpFrame, "The following database file will continue to be used:\n\r" + customStoreFileName, extensionName, JOptionPane.INFORMATION_MESSAGE);
                        }
                        preferences.setBoolean(ConfigMenu.PAUSE_LOGGING_CFG_KEY, Boolean.FALSE);
                        this.api.logging().logToOutput("SQLite logging is enabled.");
                    }
                    //Case for the CANCEL => Pause the logging
                    if (loggingQuestionReply == JOptionPane.CANCEL_OPTION) {
                        preferences.setBoolean(ConfigMenu.PAUSE_LOGGING_CFG_KEY, Boolean.TRUE);
                        this.api.logging().logToOutput("Logging is paused.");
                    }
                }
                //Save the location of the database file chosen by the user
                preferences.setString(ConfigMenu.DB_FILE_CUSTOM_LOCATION_CFG_KEY, customStoreFileName);
            } else {
                this.api.logging().logToOutput("Logging is paused.");
            }
            //Init storage and HTTP listener
            ActivityStorage activityStorage = ActivityStorageFactory.createStorage(preferences, customStoreFileName, this.api, trace);
            ActivityHttpListener activityHttpListener = new ActivityHttpListener(activityStorage, trace);
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
}
