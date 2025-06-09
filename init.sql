-- Initialize the database for Burp Suite Activity Logger
-- This script runs automatically when the container starts for the first time

-- Grant necessary permissions to the burp_user
GRANT ALL PRIVILEGES ON DATABASE burp_activity TO burp_user;

-- Create the activity table (this will also be created by the Java extension, but having it here ensures it exists)
CREATE TABLE IF NOT EXISTS ACTIVITY (
    id SERIAL PRIMARY KEY,
    local_source_ip TEXT,
    target_url TEXT,
    http_method TEXT,
    burp_tool TEXT,
    request_raw TEXT,
    send_datetime TIMESTAMP,
    http_status_code TEXT,
    response_raw TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Grant permissions on the table
GRANT ALL PRIVILEGES ON TABLE ACTIVITY TO burp_user;
GRANT USAGE, SELECT ON SEQUENCE activity_id_seq TO burp_user;

-- Create indexes for better performance on common queries
CREATE INDEX IF NOT EXISTS idx_activity_send_datetime ON ACTIVITY(send_datetime);
CREATE INDEX IF NOT EXISTS idx_activity_http_method ON ACTIVITY(http_method);
CREATE INDEX IF NOT EXISTS idx_activity_burp_tool ON ACTIVITY(burp_tool);
CREATE INDEX IF NOT EXISTS idx_activity_target_url ON ACTIVITY(target_url);

-- Log initialization completion
DO $$
BEGIN
    RAISE NOTICE 'Burp Activity Logger database initialized successfully';
END $$; 