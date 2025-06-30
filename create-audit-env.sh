#!/bin/bash

# Burp Audit Environment Creator
# This script creates Docker Compose files for different security audit environments

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 <audit_name> [options]"
    echo ""
    echo "Options:"
    echo "  --port <port>        PostgreSQL port (default: auto-assigned)"
    echo "  --pgadmin-port <port> pgAdmin port (default: auto-assigned)"
    echo "  --db-name <name>     Database name (default: burp_activity_<audit_name>)"
    echo "  --user <username>    Database username (default: burp_user_<audit_name>)"
    echo "  --password <pass>    Database password (default: burp_password_<audit_name>)"
    echo "  --no-pgadmin         Skip pgAdmin service"
    echo "  --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 audit_a"
    echo "  $0 audit_b --port 5434 --pgadmin-port 8082"
    echo "  $0 client_x --db-name burp_client_x --user client_user"
}

# Function to generate port numbers
generate_port() {
    local base_port=$1
    local audit_name=$2
    local port_offset=0
    
    # Simple hash function to generate consistent port offsets
    for ((i=0; i<${#audit_name}; i++)); do
        port_offset=$((port_offset + $(printf '%d' "'${audit_name:$i:1}")))
    done
    port_offset=$((port_offset % 1000))  # Keep it reasonable
    
    echo $((base_port + port_offset))
}

# Function to create Docker Compose file
create_docker_compose() {
    local audit_name=$1
    local postgres_port=$2
    local pgadmin_port=$3
    local db_name=$4
    local db_user=$5
    local db_password=$6
    local include_pgadmin=$7
    
    local environments_dir="environments"
    local filename="${environments_dir}/docker-compose-${audit_name}.yml"
    
    # Create environments directory if it doesn't exist
    mkdir -p "$environments_dir"
    
    print_status "Creating Docker Compose file: $filename"
    
    cat > "$filename" << EOF
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: burp-activity-db-${audit_name}
    environment:
      POSTGRES_DB: ${db_name}
      POSTGRES_USER: ${db_user}
      POSTGRES_PASSWORD: ${db_password}
      POSTGRES_INITDB_ARGS: "--encoding=UTF8"
    ports:
      - "${postgres_port}:5432"
    volumes:
      - postgres_data_${audit_name}:/var/lib/postgresql/data
      - ../../init.sql:/docker-entrypoint-initdb.d/init.sql
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${db_user} -d ${db_name}"]
      interval: 10s
      timeout: 5s
      retries: 5
EOF

    if [ "$include_pgadmin" = true ]; then
        cat >> "$filename" << EOF

  # Optional: pgAdmin for database management
  pgadmin:
    image: dpage/pgadmin4:latest
    container_name: burp-pgadmin-${audit_name}
    environment:
      PGADMIN_DEFAULT_EMAIL: admin@example.com
      PGADMIN_DEFAULT_PASSWORD: admin
      PGADMIN_CONFIG_SERVER_MODE: 'False'
    ports:
      - "${pgadmin_port}:80"
    depends_on:
      - postgres
    restart: unless-stopped
    profiles:
      - admin
EOF
    fi

    cat >> "$filename" << EOF

volumes:
  postgres_data_${audit_name}:
    driver: local
EOF

    print_status "Docker Compose file created successfully!"
}

# Function to create environment configuration file
create_env_config() {
    local audit_name=$1
    local postgres_port=$2
    local db_name=$3
    local db_user=$4
    local db_password=$5
    
    local environments_dir="environments"
    local filename="${environments_dir}/${audit_name}-config.txt"
    
    # Create environments directory if it doesn't exist
    mkdir -p "$environments_dir"
    
    print_status "Creating configuration file: $filename"
    
    cat > "$filename" << EOF
# Burp Extension Configuration for ${audit_name}
# Copy these settings to your Burp Suite extension configuration

Host: localhost
Port: ${postgres_port}
Database: ${db_name}
Username: ${db_user}
Password: ${db_password}

# Docker commands for this environment:
# Start: docker-compose -f environments/docker-compose-${audit_name}.yml up -d
# Stop:  docker-compose -f environments/docker-compose-${audit_name}.yml down
# Logs:  docker-compose -f environments/docker-compose-${audit_name}.yml logs -f

# pgAdmin (if enabled):
# URL: http://localhost:${pgadmin_port}
# Email: admin@example.com
# Password: admin
EOF

    print_status "Configuration file created: $filename"
}

# Function to create management script
create_management_script() {
    local audit_name=$1
    
    local environments_dir="environments"
    local filename="${environments_dir}/manage-${audit_name}.sh"
    
    # Create environments directory if it doesn't exist
    mkdir -p "$environments_dir"
    
    print_status "Creating management script: $filename"
    
    cat > "$filename" << 'EOF'
#!/bin/bash

# Management script for audit environment: AUDIT_NAME_PLACEHOLDER

AUDIT_NAME="AUDIT_NAME_PLACEHOLDER"
COMPOSE_FILE="docker-compose-${AUDIT_NAME}.yml"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

case "$1" in
    "start")
        print_status "Starting ${AUDIT_NAME} environment..."
        docker-compose -f "$COMPOSE_FILE" up -d
        print_status "${AUDIT_NAME} environment started successfully!"
        ;;
    "stop")
        print_status "Stopping ${AUDIT_NAME} environment..."
        docker-compose -f "$COMPOSE_FILE" down
        print_status "${AUDIT_NAME} environment stopped successfully!"
        ;;
    "restart")
        print_status "Restarting ${AUDIT_NAME} environment..."
        docker-compose -f "$COMPOSE_FILE" down
        docker-compose -f "$COMPOSE_FILE" up -d
        print_status "${AUDIT_NAME} environment restarted successfully!"
        ;;
    "logs")
        print_status "Showing logs for ${AUDIT_NAME} environment..."
        docker-compose -f "$COMPOSE_FILE" logs -f
        ;;
    "status")
        print_status "Checking status of ${AUDIT_NAME} environment..."
        docker-compose -f "$COMPOSE_FILE" ps
        ;;
    "clean")
        print_warning "This will remove all data for ${AUDIT_NAME} environment!"
        read -p "Are you sure? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_status "Cleaning ${AUDIT_NAME} environment..."
            docker-compose -f "$COMPOSE_FILE" down -v
            print_status "${AUDIT_NAME} environment cleaned successfully!"
        else
            print_status "Clean operation cancelled."
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|logs|status|clean}"
        echo ""
        echo "Commands:"
        echo "  start   - Start the environment"
        echo "  stop    - Stop the environment"
        echo "  restart - Restart the environment"
        echo "  logs    - Show logs"
        echo "  status  - Show container status"
        echo "  clean   - Stop and remove all data (DESTRUCTIVE)"
        exit 1
        ;;
esac
EOF

    # Replace placeholder with actual audit name
    sed -i '' "s/AUDIT_NAME_PLACEHOLDER/${audit_name}/g" "$filename"
    
    # Make the script executable
    chmod +x "$filename"
    
    print_status "Management script created: $filename"
}

# Main script logic
main() {
    if [ $# -eq 0 ]; then
        print_error "No audit name provided"
        show_usage
        exit 1
    fi
    
    if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        show_usage
        exit 0
    fi
    
    local audit_name=$1
    shift
    
    # Default values
    local postgres_port=""
    local pgadmin_port=""
    local db_name="burp_activity_${audit_name}"
    local db_user="burp_user_${audit_name}"
    local db_password="burp_password_${audit_name}"
    local include_pgadmin=true
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --port)
                postgres_port="$2"
                shift 2
                ;;
            --pgadmin-port)
                pgadmin_port="$2"
                shift 2
                ;;
            --db-name)
                db_name="$2"
                shift 2
                ;;
            --user)
                db_user="$2"
                shift 2
                ;;
            --password)
                db_password="$2"
                shift 2
                ;;
            --no-pgadmin)
                include_pgadmin=false
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Generate ports if not provided
    if [ -z "$postgres_port" ]; then
        postgres_port=$(generate_port 5433 "$audit_name")
    fi
    
    if [ "$include_pgadmin" = true ] && [ -z "$pgadmin_port" ]; then
        pgadmin_port=$(generate_port 8081 "$audit_name")
    fi
    
    print_header "Creating Audit Environment: $audit_name"
    print_status "Audit Name: $audit_name"
    print_status "PostgreSQL Port: $postgres_port"
    if [ "$include_pgadmin" = true ]; then
        print_status "pgAdmin Port: $pgadmin_port"
    fi
    print_status "Database: $db_name"
    print_status "Username: $db_user"
    print_status "Include pgAdmin: $include_pgadmin"
    
    # Check if files already exist
    if [ -f "environments/docker-compose-${audit_name}.yml" ]; then
        print_warning "Docker Compose file already exists: environments/docker-compose-${audit_name}.yml"
        read -p "Overwrite? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "Operation cancelled."
            exit 0
        fi
    fi
    
    # Create the files
    create_docker_compose "$audit_name" "$postgres_port" "$pgadmin_port" "$db_name" "$db_user" "$db_password" "$include_pgadmin"
    create_env_config "$audit_name" "$postgres_port" "$db_name" "$db_user" "$db_password"
    create_management_script "$audit_name"
    
    print_header "Environment Creation Complete!"
    print_status "Files created:"
    echo "  - environments/docker-compose-${audit_name}.yml"
    echo "  - environments/${audit_name}-config.txt"
    echo "  - environments/manage-${audit_name}.sh"
    echo ""
    print_status "Next steps:"
    echo "  1. Review the configuration in environments/${audit_name}-config.txt"
    echo "  2. Start the environment: ./environments/manage-${audit_name}.sh start"
    echo "  3. Configure your Burp extension with the provided settings"
    echo "  4. Access pgAdmin at http://localhost:${pgadmin_port} (if enabled)"
}

# Run main function with all arguments
main "$@" 