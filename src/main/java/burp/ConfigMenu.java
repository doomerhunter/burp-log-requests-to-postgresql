package burp;

import javax.swing.AbstractAction;
import javax.swing.JCheckBoxMenuItem;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JCheckBox;
import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;
import java.awt.GridLayout;
import java.io.File;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;

/**
 * Menu to configure the extension options.
 */
public class ConfigMenu implements Runnable {


    /**
     * Expose the configuration option for the restriction of the logging of requests in defined target scope.
     */
    static volatile boolean ONLY_INCLUDE_REQUESTS_FROM_SCOPE = Boolean.FALSE;

    /**
     * Expose the configuration option for the exclusion of the image resource requests from the logging.
     */
    static volatile boolean EXCLUDE_IMAGE_RESOURCE_REQUESTS = Boolean.FALSE;

    /**
     * Expose the configuration option for the logging of the HTTP response content.
     */
    static volatile boolean INCLUDE_HTTP_RESPONSE_CONTENT = Boolean.FALSE;

    /**
     * Expose the list of all possible extensions of image resource to work in combination with the option "EXCLUDE_IMAGE_RESOURCE_REQUESTS".
     */
    static final List<String> IMAGE_RESOURCE_EXTENSIONS = new ArrayList<>();

    /**
     * Expose the configuration option to allow the user to pause the logging.
     */
    static volatile boolean IS_LOGGING_PAUSED = Boolean.FALSE;

    /**
     * Expose the configuration option to choose storage type (SQLite or PostgreSQL).
     */
    static volatile boolean USE_POSTGRESQL = Boolean.FALSE;

    /**
     * Expose the configuration option for filtering requests by tool source.
     */
    static volatile boolean FILTER_BY_TOOL_SOURCE = Boolean.FALSE;

    /**
     * Expose the list of included tools when tool source filtering is enabled.
     */
    static final List<String> INCLUDED_TOOL_SOURCES = new ArrayList<>();

    /**
     * Option configuration key for the restriction of the logging of requests in defined target scope.
     */
    private static final String ONLY_INCLUDE_REQUESTS_FROM_SCOPE_CFG_KEY = "ONLY_INCLUDE_REQUESTS_FROM_SCOPE";

    /**
     * Option configuration key for the exclusion of the image resource requests from the logging.
     */
    private static final String EXCLUDE_IMAGE_RESOURCE_REQUESTS_CFG_KEY = "EXCLUDE_IMAGE_RESOURCE_REQUESTS";

    /**
     * Option configuration key to allow the user to use a custom location and name for the DB file.
     */
    public static final String DB_FILE_CUSTOM_LOCATION_CFG_KEY = "DB_FILE_CUSTOM_LOCATION";

    /**
     * Option configuration key to allow the user to pause the logging.
     */
    public static final String PAUSE_LOGGING_CFG_KEY = "PAUSE_LOGGING";

    /**
     * Option configuration key for the logging of the HTTP response content.
     */
    public static final String INCLUDE_HTTP_RESPONSE_CONTENT_CFG_KEY = "INCLUDE_HTTP_RESPONSE_CONTENT";

    /**
     * Option configuration key for using PostgreSQL instead of SQLite.
     */
    public static final String USE_POSTGRESQL_CFG_KEY = "USE_POSTGRESQL";

    /**
     * PostgreSQL configuration keys.
     */
    public static final String POSTGRESQL_HOST_CFG_KEY = "POSTGRESQL_HOST";
    public static final String POSTGRESQL_PORT_CFG_KEY = "POSTGRESQL_PORT";
    public static final String POSTGRESQL_DATABASE_CFG_KEY = "POSTGRESQL_DATABASE";
    public static final String POSTGRESQL_USERNAME_CFG_KEY = "POSTGRESQL_USERNAME";
    public static final String POSTGRESQL_PASSWORD_CFG_KEY = "POSTGRESQL_PASSWORD";

    /**
     * Option configuration key for filtering requests by tool source.
     */
    public static final String FILTER_BY_TOOL_SOURCE_CFG_KEY = "FILTER_BY_TOOL_SOURCE";

    /**
     * Option configuration key for storing included tool sources.
     */
    public static final String INCLUDED_TOOL_SOURCES_CFG_KEY = "INCLUDED_TOOL_SOURCES";

    /**
     * Extension root configuration menu.
     */
    private JMenu cfgMenu;

    /**
     * The MontoyaAPI object used for accessing all the Burp features and ressources such as requests and responses.
     */
    private MontoyaApi api;

    /**
     * Access the persistent preferences from the user settings in Burp.
     */
    private Preferences preferences;

    /**
     * Ref on project logger.
     */
    private Trace trace;

    /**
     * Ref on activity storage in order to enable the access to the DB statistics.
     */
    private ActivityStorage activityStorage;

    /**
     * Ref on activity HTTP listener to enable storage replacement.
     */
    private ActivityHttpListener activityHttpListener;

    /**
     * Constructor.
     *
     * @param api             The MontoyaAPI object used for accessing all the Burp features and ressources such as requests and responses.
     * @param trace           Ref on project logger.
     * @param activityStorage Ref on activity storage in order to enable the access to the DB statistics.
     * @param activityHttpListener Ref on activity HTTP listener to enable storage replacement.
     */
    ConfigMenu(MontoyaApi api, Trace trace, ActivityStorage activityStorage, ActivityHttpListener activityHttpListener) {
        this.api = api;
        this.trace = trace;
        this.activityStorage = activityStorage;
        this.activityHttpListener = activityHttpListener;
        this.preferences = this.api.persistence().preferences();

        String value;
        //Load the extension settings
        if (IMAGE_RESOURCE_EXTENSIONS.isEmpty()) {
            ResourceBundle settingsBundle = ResourceBundle.getBundle("settings");
            value = settingsBundle.getString("image.extensions").replaceAll(" ", "").toLowerCase(Locale.US);
            Collections.addAll(IMAGE_RESOURCE_EXTENSIONS, value.split(","));
            this.trace.writeLog("Image resource extensions list successfully loaded: " + IMAGE_RESOURCE_EXTENSIONS.toString());
        }

        //Load the save state of the options
        ONLY_INCLUDE_REQUESTS_FROM_SCOPE = Boolean.TRUE.equals(this.preferences.getBoolean(ONLY_INCLUDE_REQUESTS_FROM_SCOPE_CFG_KEY));
        EXCLUDE_IMAGE_RESOURCE_REQUESTS = Boolean.TRUE.equals(this.preferences.getBoolean(EXCLUDE_IMAGE_RESOURCE_REQUESTS_CFG_KEY));
        IS_LOGGING_PAUSED = Boolean.TRUE.equals(this.preferences.getBoolean(PAUSE_LOGGING_CFG_KEY));
        INCLUDE_HTTP_RESPONSE_CONTENT = Boolean.TRUE.equals(this.preferences.getBoolean(INCLUDE_HTTP_RESPONSE_CONTENT_CFG_KEY));
        USE_POSTGRESQL = Boolean.TRUE.equals(this.preferences.getBoolean(USE_POSTGRESQL_CFG_KEY));
        FILTER_BY_TOOL_SOURCE = Boolean.TRUE.equals(this.preferences.getBoolean(FILTER_BY_TOOL_SOURCE_CFG_KEY));
        
        // Load included tool sources from preferences
        String includedToolsStr = this.preferences.getString(INCLUDED_TOOL_SOURCES_CFG_KEY);
        if (includedToolsStr != null && !includedToolsStr.trim().isEmpty()) {
            String[] includedTools = includedToolsStr.split(",");
            for (String tool : includedTools) {
                String trimmedTool = tool.trim();
                if (!trimmedTool.isEmpty()) {
                    INCLUDED_TOOL_SOURCES.add(trimmedTool);
                }
            }
        } else {
            // Default: include all tools if no preference is set
            Collections.addAll(INCLUDED_TOOL_SOURCES, "Proxy", "Repeater", "Intruder", "Scanner", "Sequencer", "Spider", "Target", "Extender");
        }
    }

    /**
     * Build the options menu used to configure the extension.
     */
    @Override
    public void run() {
        //Build the menu
        this.cfgMenu = new JMenu("Log Requests to Database");
        //Add the sub menu to restrict the logging of requests in defined target scope
        String menuText = "Log only requests from defined target scope";
        final JCheckBoxMenuItem subMenuRestrictToScope = new JCheckBoxMenuItem(menuText, ONLY_INCLUDE_REQUESTS_FROM_SCOPE);
        subMenuRestrictToScope.addActionListener(new AbstractAction(menuText) {
            public void actionPerformed(ActionEvent e) {
                if (subMenuRestrictToScope.isSelected()) {
                    ConfigMenu.this.preferences.setBoolean(ONLY_INCLUDE_REQUESTS_FROM_SCOPE_CFG_KEY, Boolean.TRUE);
                    ConfigMenu.ONLY_INCLUDE_REQUESTS_FROM_SCOPE = Boolean.TRUE;
                    ConfigMenu.this.trace.writeLog("From now, only requests from defined target scope will be logged.");
                } else {
                    ConfigMenu.this.preferences.setBoolean(ONLY_INCLUDE_REQUESTS_FROM_SCOPE_CFG_KEY, Boolean.FALSE);
                    ConfigMenu.ONLY_INCLUDE_REQUESTS_FROM_SCOPE = Boolean.FALSE;
                    ConfigMenu.this.trace.writeLog("From now, requests that are not in defined target scope will be also logged.");
                }
            }
        });
        this.cfgMenu.add(subMenuRestrictToScope);
        //Add the sub menu to exclude the image resource requests from the logging.
        menuText = "Exclude the image resource requests";
        final JCheckBoxMenuItem subMenuExcludeImageResources = new JCheckBoxMenuItem(menuText, EXCLUDE_IMAGE_RESOURCE_REQUESTS);
        subMenuExcludeImageResources.addActionListener(new AbstractAction(menuText) {
            public void actionPerformed(ActionEvent e) {
                if (subMenuExcludeImageResources.isSelected()) {
                    ConfigMenu.this.preferences.setBoolean(EXCLUDE_IMAGE_RESOURCE_REQUESTS_CFG_KEY, Boolean.TRUE);
                    ConfigMenu.EXCLUDE_IMAGE_RESOURCE_REQUESTS = Boolean.TRUE;
                    ConfigMenu.this.trace.writeLog("From now, requests for image resource will not be logged.");
                } else {
                    ConfigMenu.this.preferences.setBoolean(EXCLUDE_IMAGE_RESOURCE_REQUESTS_CFG_KEY, Boolean.FALSE);
                    ConfigMenu.EXCLUDE_IMAGE_RESOURCE_REQUESTS = Boolean.FALSE;
                    ConfigMenu.this.trace.writeLog("From now, requests for image resource will be logged.");
                }
            }
        });
        this.cfgMenu.add(subMenuExcludeImageResources);
        //Add the menu to include the HTTP responses content in the logging
        menuText = "Include the responses content";
        final JCheckBoxMenuItem subMenuIncludeHttpResponseContent = new JCheckBoxMenuItem(menuText, INCLUDE_HTTP_RESPONSE_CONTENT);
        subMenuIncludeHttpResponseContent.addActionListener(new AbstractAction(menuText) {
            public void actionPerformed(ActionEvent e) {
                if (subMenuIncludeHttpResponseContent.isSelected()) {
                    ConfigMenu.this.preferences.setBoolean(INCLUDE_HTTP_RESPONSE_CONTENT_CFG_KEY, Boolean.TRUE);
                    ConfigMenu.INCLUDE_HTTP_RESPONSE_CONTENT = Boolean.TRUE;
                    ConfigMenu.this.trace.writeLog("From now, responses content will be logged.");
                } else {
                    ConfigMenu.this.preferences.setBoolean(INCLUDE_HTTP_RESPONSE_CONTENT_CFG_KEY, Boolean.FALSE);
                    ConfigMenu.INCLUDE_HTTP_RESPONSE_CONTENT = Boolean.FALSE;
                    ConfigMenu.this.trace.writeLog("From now, responses content will not be logged.");
                }
            }
        });
        this.cfgMenu.add(subMenuIncludeHttpResponseContent);
        //Add the menu to choose storage type
        menuText = "Use PostgreSQL instead of SQLite";
        final JCheckBoxMenuItem subMenuUsePostgreSQL = new JCheckBoxMenuItem(menuText, USE_POSTGRESQL);
        subMenuUsePostgreSQL.addActionListener(new AbstractAction(menuText) {
            public void actionPerformed(ActionEvent e) {
                if (subMenuUsePostgreSQL.isSelected()) {
                    // Show PostgreSQL configuration dialog
                    if (ActivityStorageFactory.showPostgreSQLConfigDialog(ConfigMenu.this.preferences, ConfigMenu.getBurpFrame())) {
                        try {
                            ConfigMenu.this.preferences.setBoolean(USE_POSTGRESQL_CFG_KEY, Boolean.TRUE);
                            ConfigMenu.USE_POSTGRESQL = Boolean.TRUE;
                            
                            // Create new PostgreSQL storage
                            String defaultStoreFileName = new File(System.getProperty("user.home"), "LogRequestsToSQLite.db").getAbsolutePath().replaceAll("\\\\", "/");
                            String customStoreFileName = ConfigMenu.this.preferences.getString(ConfigMenu.DB_FILE_CUSTOM_LOCATION_CFG_KEY);
                            if (customStoreFileName == null) {
                                customStoreFileName = defaultStoreFileName;
                            }
                            
                            ActivityStorage newStorage = ActivityStorageFactory.createStorage(
                                ConfigMenu.this.preferences, 
                                customStoreFileName, 
                                ConfigMenu.this.api, 
                                ConfigMenu.this.trace
                            );
                            
                            // Replace storage without restart
                            ConfigMenu.this.replaceActivityStorage(newStorage);
                            
                            ConfigMenu.this.trace.writeLog("PostgreSQL storage enabled and active.");
                            JOptionPane.showMessageDialog(ConfigMenu.getBurpFrame(), 
                                "PostgreSQL storage is now active. No restart required!", 
                                "Configuration Updated", 
                                JOptionPane.INFORMATION_MESSAGE);
                        } catch (Exception ex) {
                            ConfigMenu.this.trace.writeLog("Failed to switch to PostgreSQL storage: " + ex.getMessage());
                            JOptionPane.showMessageDialog(ConfigMenu.getBurpFrame(), 
                                "Failed to switch to PostgreSQL storage: " + ex.getMessage() + 
                                "\nPlease check your PostgreSQL configuration and try again.", 
                                "Configuration Error", 
                                JOptionPane.ERROR_MESSAGE);
                            // Revert checkbox state
                            subMenuUsePostgreSQL.setSelected(false);
                            ConfigMenu.this.preferences.setBoolean(USE_POSTGRESQL_CFG_KEY, Boolean.FALSE);
                            ConfigMenu.USE_POSTGRESQL = Boolean.FALSE;
                        }
                    } else {
                        // User cancelled, revert checkbox
                        subMenuUsePostgreSQL.setSelected(false);
                    }
                } else {
                    try {
                        ConfigMenu.this.preferences.setBoolean(USE_POSTGRESQL_CFG_KEY, Boolean.FALSE);
                        ConfigMenu.USE_POSTGRESQL = Boolean.FALSE;
                        
                        // Create new SQLite storage
                        String defaultStoreFileName = new File(System.getProperty("user.home"), "LogRequestsToSQLite.db").getAbsolutePath().replaceAll("\\\\", "/");
                        String customStoreFileName = ConfigMenu.this.preferences.getString(ConfigMenu.DB_FILE_CUSTOM_LOCATION_CFG_KEY);
                        if (customStoreFileName == null) {
                            customStoreFileName = defaultStoreFileName;
                        }
                        
                        ActivityStorage newStorage = ActivityStorageFactory.createStorage(
                            ConfigMenu.this.preferences, 
                            customStoreFileName, 
                            ConfigMenu.this.api, 
                            ConfigMenu.this.trace
                        );
                        
                        // Replace storage without restart
                        ConfigMenu.this.replaceActivityStorage(newStorage);
                        
                        ConfigMenu.this.trace.writeLog("SQLite storage enabled and active.");
                        JOptionPane.showMessageDialog(ConfigMenu.getBurpFrame(), 
                            "SQLite storage is now active. No restart required!", 
                            "Configuration Updated", 
                            JOptionPane.INFORMATION_MESSAGE);
                    } catch (Exception ex) {
                        ConfigMenu.this.trace.writeLog("Failed to switch to SQLite storage: " + ex.getMessage());
                        JOptionPane.showMessageDialog(ConfigMenu.getBurpFrame(), 
                            "Failed to switch to SQLite storage: " + ex.getMessage(), 
                            "Configuration Error", 
                            JOptionPane.ERROR_MESSAGE);
                        // Revert checkbox state
                        subMenuUsePostgreSQL.setSelected(true);
                        ConfigMenu.this.preferences.setBoolean(USE_POSTGRESQL_CFG_KEY, Boolean.TRUE);
                        ConfigMenu.USE_POSTGRESQL = Boolean.TRUE;
                    }
                }
            }
        });
        this.cfgMenu.add(subMenuUsePostgreSQL);
        //Add the menu to configure PostgreSQL connection
        menuText = "Configure PostgreSQL Connection";
        final JMenuItem subMenuConfigurePostgreSQL = new JMenuItem(menuText);
        subMenuConfigurePostgreSQL.addActionListener(new AbstractAction(menuText) {
            public void actionPerformed(ActionEvent e) {
                if (ActivityStorageFactory.showPostgreSQLConfigDialog(ConfigMenu.this.preferences, ConfigMenu.getBurpFrame())) {
                    try {
                        // If currently using PostgreSQL, update the connection
                        if (ConfigMenu.USE_POSTGRESQL) {
                            String defaultStoreFileName = new File(System.getProperty("user.home"), "LogRequestsToSQLite.db").getAbsolutePath().replaceAll("\\\\", "/");
                            String customStoreFileName = ConfigMenu.this.preferences.getString(ConfigMenu.DB_FILE_CUSTOM_LOCATION_CFG_KEY);
                            if (customStoreFileName == null) {
                                customStoreFileName = defaultStoreFileName;
                            }
                            
                            ActivityStorage newStorage = ActivityStorageFactory.createStorage(
                                ConfigMenu.this.preferences, 
                                customStoreFileName, 
                                ConfigMenu.this.api, 
                                ConfigMenu.this.trace
                            );
                            
                            // Replace storage without restart
                            ConfigMenu.this.replaceActivityStorage(newStorage);
                            
                            ConfigMenu.this.trace.writeLog("PostgreSQL connection parameters updated and reconnected.");
                            JOptionPane.showMessageDialog(ConfigMenu.getBurpFrame(), 
                                "PostgreSQL connection updated and active. No restart required!", 
                                "Configuration Updated", 
                                JOptionPane.INFORMATION_MESSAGE);
                        } else {
                            ConfigMenu.this.trace.writeLog("PostgreSQL connection parameters updated.");
                            JOptionPane.showMessageDialog(ConfigMenu.getBurpFrame(), 
                                "PostgreSQL connection parameters saved. Enable PostgreSQL storage to use the new settings.", 
                                "Configuration Updated", 
                                JOptionPane.INFORMATION_MESSAGE);
                        }
                    } catch (Exception ex) {
                        ConfigMenu.this.trace.writeLog("Failed to update PostgreSQL connection: " + ex.getMessage());
                        JOptionPane.showMessageDialog(ConfigMenu.getBurpFrame(), 
                            "Failed to update PostgreSQL connection: " + ex.getMessage() + 
                            "\nPlease check your PostgreSQL configuration and try again.", 
                            "Configuration Error", 
                            JOptionPane.ERROR_MESSAGE);
                    }
                }
            }
        });
        this.cfgMenu.add(subMenuConfigurePostgreSQL);
        //Add the menu to filter by tool source
        menuText = "Select tools to log";
        final JCheckBoxMenuItem subMenuFilterByToolSource = new JCheckBoxMenuItem(menuText, FILTER_BY_TOOL_SOURCE);
        subMenuFilterByToolSource.addActionListener(new AbstractAction(menuText) {
            public void actionPerformed(ActionEvent e) {
                if (subMenuFilterByToolSource.isSelected()) {
                    // Show dialog with checkboxes for each tool
                    if (showToolSelectionDialog()) {
                        ConfigMenu.this.preferences.setBoolean(FILTER_BY_TOOL_SOURCE_CFG_KEY, Boolean.TRUE);
                        ConfigMenu.this.preferences.setString(INCLUDED_TOOL_SOURCES_CFG_KEY, String.join(",", INCLUDED_TOOL_SOURCES));
                        FILTER_BY_TOOL_SOURCE = Boolean.TRUE;
                        
                        ConfigMenu.this.trace.writeLog("Tool source filtering enabled. Included tools: " + INCLUDED_TOOL_SOURCES.toString());
                    } else {
                        // User cancelled, uncheck the menu item
                        subMenuFilterByToolSource.setSelected(false);
                    }
                } else {
                    ConfigMenu.this.preferences.setBoolean(FILTER_BY_TOOL_SOURCE_CFG_KEY, Boolean.FALSE);
                    FILTER_BY_TOOL_SOURCE = Boolean.FALSE;
                    // Reset to include all tools
                    INCLUDED_TOOL_SOURCES.clear();
                    Collections.addAll(INCLUDED_TOOL_SOURCES, "Proxy", "Repeater", "Intruder", "Scanner", "Sequencer", "Spider", "Target", "Extender");
                    ConfigMenu.this.trace.writeLog("Tool source filtering disabled. All tools will be logged.");
                }
            }
        });
        this.cfgMenu.add(subMenuFilterByToolSource);
        //Add the menu to pause the logging
        menuText = "Pause the logging";
        final JCheckBoxMenuItem subMenuPauseTheLogging = new JCheckBoxMenuItem(menuText, IS_LOGGING_PAUSED);
        subMenuPauseTheLogging.addActionListener(new AbstractAction(menuText) {
            public void actionPerformed(ActionEvent e) {
                if (subMenuPauseTheLogging.isSelected()) {
                    ConfigMenu.this.preferences.setBoolean(PAUSE_LOGGING_CFG_KEY, Boolean.TRUE);
                    ConfigMenu.IS_LOGGING_PAUSED = Boolean.TRUE;
                    ConfigMenu.this.trace.writeLog("From now, logging is paused.");
                } else {
                    ConfigMenu.this.preferences.setBoolean(PAUSE_LOGGING_CFG_KEY, Boolean.FALSE);
                    ConfigMenu.IS_LOGGING_PAUSED = Boolean.FALSE;
                    String dbPath = ConfigMenu.this.preferences.getString(ConfigMenu.DB_FILE_CUSTOM_LOCATION_CFG_KEY);
                    String msg = "From now, logging is enabled and stored in database file '" + dbPath + "'.";
                    ConfigMenu.this.trace.writeLog(msg);
                }
            }
        });
        this.cfgMenu.add(subMenuPauseTheLogging);
        //Add the menu to change the DB file (SQLite only)
        menuText = "Change the SQLite DB file";
        final JMenuItem subMenuDBFileLocationMenuItem = new JMenuItem(menuText);
        subMenuDBFileLocationMenuItem.addActionListener(
                new AbstractAction(menuText) {
                    public void actionPerformed(ActionEvent e) {
                        try {
                            String title = "Change the SQLite DB file";
                            if (ConfigMenu.USE_POSTGRESQL) {
                                JOptionPane.showMessageDialog(ConfigMenu.getBurpFrame(), "This option is only available when using SQLite storage.", title, JOptionPane.WARNING_MESSAGE);
                                return;
                            }
                            if (!ConfigMenu.IS_LOGGING_PAUSED) {
                                JOptionPane.showMessageDialog(ConfigMenu.getBurpFrame(), "Logging must be paused prior to update the DB file location!", title, JOptionPane.WARNING_MESSAGE);
                            } else {
                                String customStoreFileName = ConfigMenu.this.preferences.getString(ConfigMenu.DB_FILE_CUSTOM_LOCATION_CFG_KEY);
                                JFileChooser customStoreFileNameFileChooser = Utilities.createDBFileChooser();
                                int dbFileSelectionReply = customStoreFileNameFileChooser.showDialog(getBurpFrame(), "Use");
                                if (dbFileSelectionReply == JFileChooser.APPROVE_OPTION) {
                                    customStoreFileName = customStoreFileNameFileChooser.getSelectedFile().getAbsolutePath().replaceAll("\\\\", "/");
                                    // Only works with SQLite ActivityLogger
                                    if (ConfigMenu.this.activityStorage instanceof ActivityLogger) {
                                        ((ActivityLogger) ConfigMenu.this.activityStorage).updateStoreLocation(customStoreFileName);
                                        ConfigMenu.this.preferences.setString(ConfigMenu.DB_FILE_CUSTOM_LOCATION_CFG_KEY, customStoreFileName);
                                        JOptionPane.showMessageDialog(getBurpFrame(), "DB file updated to use:\n\r" + customStoreFileName, title, JOptionPane.INFORMATION_MESSAGE);
                                    } else {
                                        JOptionPane.showMessageDialog(getBurpFrame(), "This feature is only available with SQLite storage.", title, JOptionPane.WARNING_MESSAGE);
                                    }
                                } else {
                                    JOptionPane.showMessageDialog(getBurpFrame(), "The following database file will continue to be used:\n\r" + customStoreFileName, title, JOptionPane.INFORMATION_MESSAGE);
                                }
                            }
                        } catch (Exception exp) {
                            ConfigMenu.this.trace.writeLog("Cannot update DB file location: " + exp.getMessage());
                        }
                    }
                }
        );
        this.cfgMenu.add(subMenuDBFileLocationMenuItem);
        //Add the sub menu to get statistics about the DB.
        menuText = "Get statistics about the logged events";
        final JMenuItem subMenuDBStatsMenuItem = new JMenuItem(menuText);
        subMenuDBStatsMenuItem.addActionListener(
                new AbstractAction(menuText) {
                    public void actionPerformed(ActionEvent e) {
                        try {
                            //Get the data
                            DBStats stats = ConfigMenu.this.activityStorage.getEventsStats();
                            //Build the message
                            String buffer = "Size of the database file on the disk: \n\r" + formatStat(stats.getSizeOnDisk()) + ".\n\r";
                            buffer += "Amount of data sent by the biggest HTTP request: \n\r" + formatStat(stats.getBiggestRequestSize()) + ".\n\r";
                            buffer += "Total amount of data sent via HTTP requests: \n\r" + formatStat(stats.getTotalRequestsSize()) + ".\n\r";
                            buffer += "Total number of records in the database: \n\r" + stats.getTotalRecordCount() + " HTTP requests.\n\r";
                            buffer += "Maximum number of hits sent in a second: \n\r" + stats.getMaxHitsBySecond() + " Hits.";
                            //Display the information via the UI
                            JOptionPane.showMessageDialog(ConfigMenu.getBurpFrame(), buffer, "Events statistics", JOptionPane.INFORMATION_MESSAGE);
                        } catch (Exception exp) {
                            ConfigMenu.this.trace.writeLog("Cannot obtains statistics about events: " + exp.getMessage());
                        }
                    }
                }
        );
        this.cfgMenu.add(subMenuDBStatsMenuItem);

        //Register the menu in the UI.
        this.api.userInterface().menuBar().registerMenu(this.cfgMenu);
    }

    /**
     * Get a reference on the BURP main frame.
     *
     * @return BURP main frame.
     * @see "https://github.com/PortSwigger/param-miner/blob/master/src/burp/Utilities.java"
     */
    static JFrame getBurpFrame() {
        for (Frame f : Frame.getFrames()) {
            if (f.isVisible() && f.getTitle().startsWith(("Burp Suite"))) {
                return (JFrame) f;
            }
        }
        return null;
    }

    /**
     * Format a statistic value in KB, MB or GB according to the value passed.
     *
     * @param stat Number of bytes.
     * @return Formatted value.
     */
    static String formatStat(long stat) {

        //Units
        double oneKB = 1024;
        double oneMB = 1048576;
        double oneGB = 1073741824;

        //Determine the unit the use
        double unit = oneKB;
        String unitLabel = "Kb";
        if (stat >= oneGB) {
            unit = oneGB;
            unitLabel = "Gb";
        } else if (stat >= oneMB) {
            unit = oneMB;
            unitLabel = "Mb";
        }

        //Computing
        double amount = stat / unit;
        return String.format("%.2f %s", amount, unitLabel);
    }

    /**
     * Replace the current activity storage with a new one.
     * This allows switching between storage types without restarting Burp Suite.
     *
     * @param newStorage The new storage instance to use
     */
    private void replaceActivityStorage(ActivityStorage newStorage) {
        try {
            // Pause logging temporarily
            boolean wasLoggingPaused = IS_LOGGING_PAUSED;
            IS_LOGGING_PAUSED = true;
            
            // Clean up old storage
            if (this.activityStorage != null) {
                this.activityStorage.extensionUnloaded();
                this.trace.writeLog("Old activity storage cleaned up.");
            }
            
            // Replace storage instances
            this.activityStorage = newStorage;
            this.activityHttpListener.replaceStorage(newStorage);
            
            // Register new storage as unloading handler
            this.api.extension().registerUnloadingHandler(newStorage);
            
            // Restore logging state
            IS_LOGGING_PAUSED = wasLoggingPaused;
            
            this.trace.writeLog("Activity storage successfully replaced.");
        } catch (Exception e) {
            this.trace.writeLog("Error replacing activity storage: " + e.getMessage());
            throw new RuntimeException("Failed to replace activity storage", e);
        }
    }

    /**
     * Show a dialog with checkboxes for tool selection.
     *
     * @return true if user confirmed the selection, false if cancelled
     */
    private boolean showToolSelectionDialog() {
        // Include both lowercase and uppercase versions to handle API variations
        String[] allTools = {"Proxy", "Repeater", "Intruder", "Scanner", "Sequencer", "Spider", "Target", "Extender"};
        JCheckBox[] checkBoxes = new JCheckBox[allTools.length];
        
        // Create checkboxes and set their initial state based on current included tools
        for (int i = 0; i < allTools.length; i++) {
            // Check for case-insensitive match
            final String currentTool = allTools[i]; // Make it final for lambda
            boolean isChecked = INCLUDED_TOOL_SOURCES.stream()
                .anyMatch(includedTool -> includedTool.equalsIgnoreCase(currentTool));
            checkBoxes[i] = new JCheckBox(currentTool, isChecked);
        }
        
        // Create a panel to hold the checkboxes
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(0, 2)); // 2 columns
        panel.add(new JLabel("Select tools to log:"));
        panel.add(new JLabel("")); // Empty cell for spacing
        
        for (JCheckBox checkBox : checkBoxes) {
            panel.add(checkBox);
        }
        
        // Show the dialog
        int result = JOptionPane.showConfirmDialog(
            getBurpFrame(),
            panel,
            "Tool Selection",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE
        );
        
        if (result == JOptionPane.OK_OPTION) {
            // Update the included tools list based on checkbox selections
            INCLUDED_TOOL_SOURCES.clear();
            for (int i = 0; i < checkBoxes.length; i++) {
                if (checkBoxes[i].isSelected()) {
                    INCLUDED_TOOL_SOURCES.add(allTools[i]);
                }
            }
            this.trace.writeLog("Tool selection updated. New included tools: " + INCLUDED_TOOL_SOURCES.toString());
            return true;
        }
        
        return false;
    }
}
