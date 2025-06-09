package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.JPasswordField;
import javax.swing.JPanel;
import javax.swing.JLabel;
import java.awt.GridLayout;

/**
 * Factory class to create the appropriate activity storage instance based on configuration.
 */
class ActivityStorageFactory {

    /**
     * Create an activity storage instance based on configuration preferences.
     *
     * @param preferences   Preferences for configuration
     * @param storeName     SQLite database file path (used if SQLite is selected)
     * @param api           MontoyaApi instance
     * @param trace         Trace logger
     * @return              ActivityStorage instance
     * @throws Exception    If storage creation fails
     */
    static ActivityStorage createStorage(Preferences preferences, String storeName, MontoyaApi api, Trace trace) throws Exception {
        boolean usePostgreSQL = Boolean.TRUE.equals(preferences.getBoolean(ConfigMenu.USE_POSTGRESQL_CFG_KEY));
        
        if (usePostgreSQL) {
            return createPostgreSQLStorage(preferences, api, trace);
        } else {
            return createSQLiteStorage(storeName, api, trace);
        }
    }

    /**
     * Create SQLite storage instance.
     */
    private static ActivityStorage createSQLiteStorage(String storeName, MontoyaApi api, Trace trace) throws Exception {
        return new ActivityLogger(storeName, api, trace);
    }

    /**
     * Create PostgreSQL storage instance.
     */
    private static ActivityStorage createPostgreSQLStorage(Preferences preferences, MontoyaApi api, Trace trace) throws Exception {
        String host = preferences.getString(ConfigMenu.POSTGRESQL_HOST_CFG_KEY);
        String portStr = preferences.getString(ConfigMenu.POSTGRESQL_PORT_CFG_KEY);
        String database = preferences.getString(ConfigMenu.POSTGRESQL_DATABASE_CFG_KEY);
        String username = preferences.getString(ConfigMenu.POSTGRESQL_USERNAME_CFG_KEY);
        String password = preferences.getString(ConfigMenu.POSTGRESQL_PASSWORD_CFG_KEY);

        // Set defaults if not configured
        if (host == null || host.trim().isEmpty()) {
            host = "localhost";
        }
        
        int port = 5432; // Default PostgreSQL port
        if (portStr != null && !portStr.trim().isEmpty()) {
            try {
                port = Integer.parseInt(portStr.trim());
            } catch (NumberFormatException e) {
                trace.writeLog("Invalid PostgreSQL port, using default 5432");
            }
        }
        
        if (database == null || database.trim().isEmpty()) {
            database = "burp_requests";
        }
        
        if (username == null || username.trim().isEmpty()) {
            username = "postgres";
        }
        
        if (password == null) {
            password = "";
        }

        return new PostgreSQLActivityLogger(host, port, database, username, password, api, trace);
    }

    /**
     * Show PostgreSQL connection configuration dialog.
     *
     * @param preferences   Preferences to save configuration
     * @param parentFrame   Parent frame for dialog
     * @return              true if user confirmed, false if cancelled
     */
    static boolean showPostgreSQLConfigDialog(Preferences preferences, JFrame parentFrame) {
        JPanel panel = new JPanel(new GridLayout(5, 2, 5, 5));
        
        String currentHost = preferences.getString(ConfigMenu.POSTGRESQL_HOST_CFG_KEY);
        String currentPort = preferences.getString(ConfigMenu.POSTGRESQL_PORT_CFG_KEY);
        String currentDatabase = preferences.getString(ConfigMenu.POSTGRESQL_DATABASE_CFG_KEY);
        String currentUsername = preferences.getString(ConfigMenu.POSTGRESQL_USERNAME_CFG_KEY);
        String currentPassword = preferences.getString(ConfigMenu.POSTGRESQL_PASSWORD_CFG_KEY);

        JTextField hostField = new JTextField(currentHost != null ? currentHost : "localhost");
        JTextField portField = new JTextField(currentPort != null ? currentPort : "5432");
        JTextField databaseField = new JTextField(currentDatabase != null ? currentDatabase : "burp_requests");
        JTextField usernameField = new JTextField(currentUsername != null ? currentUsername : "postgres");
        JPasswordField passwordField = new JPasswordField(currentPassword != null ? currentPassword : "");

        panel.add(new JLabel("Host:"));
        panel.add(hostField);
        panel.add(new JLabel("Port:"));
        panel.add(portField);
        panel.add(new JLabel("Database:"));
        panel.add(databaseField);
        panel.add(new JLabel("Username:"));
        panel.add(usernameField);
        panel.add(new JLabel("Password:"));
        panel.add(passwordField);

        int result = JOptionPane.showConfirmDialog(
            parentFrame,
            panel,
            "PostgreSQL Connection Configuration",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE
        );

        if (result == JOptionPane.OK_OPTION) {
            // Save configuration
            preferences.setString(ConfigMenu.POSTGRESQL_HOST_CFG_KEY, hostField.getText().trim());
            preferences.setString(ConfigMenu.POSTGRESQL_PORT_CFG_KEY, portField.getText().trim());
            preferences.setString(ConfigMenu.POSTGRESQL_DATABASE_CFG_KEY, databaseField.getText().trim());
            preferences.setString(ConfigMenu.POSTGRESQL_USERNAME_CFG_KEY, usernameField.getText().trim());
            preferences.setString(ConfigMenu.POSTGRESQL_PASSWORD_CFG_KEY, new String(passwordField.getPassword()));
            return true;
        }

        return false;
    }
} 