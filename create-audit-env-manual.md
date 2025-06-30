#!/bin/bash

# Burp Audit Environment Creator - Examples

This guide demonstrates how to create different audit environments using the `create-audit-env.sh` script.

## Example 1: Basic Audit Environment

Create a basic audit environment with default settings:

```bash
./create-audit-env.sh audit_a
```

## Example 2: Custom Ports

Create an audit environment with custom PostgreSQL and pgAdmin ports:

```bash
./create-audit-env.sh audit_b --port 5434 --pgadmin-port 8082
```

## Example 3: Custom Database Configuration

Create an audit environment with custom database settings:

```bash
./create-audit-env.sh client_x --db-name burp_client_x --user client_user --password secure_pass123
```

## Example 4: Without pgAdmin

Create an audit environment without pgAdmin interface:

```bash
./create-audit-env.sh audit_c --no-pgadmin
```

## Example 5: Multiple Environments

Create multiple environments for different clients:

```bash
./create-audit-env.sh client_alpha --port 5435 --pgadmin-port 8083
./create-audit-env.sh client_beta --port 5436 --pgadmin-port 8084
./create-audit-env.sh client_gamma --port 5437 --pgadmin-port 8085
```

## Management Commands

After creating an environment, you can manage it with these commands:

```bash
./manage-<audit_name>.sh start    # Start the environment
./manage-<audit_name>.sh stop     # Stop the environment
./manage-<audit_name>.sh restart  # Restart the environment
./manage-<audit_name>.sh logs     # View logs
./manage-<audit_name>.sh status   # Check status
./manage-<audit_name>.sh clean    # Remove all data (DESTRUCTIVE)
```

## Burp Extension Configuration

Each environment creates a config file (`<audit_name>-config.txt`). Use those settings in your Burp Suite extension configuration.

## Port Assignment

If you don't specify ports, the script will auto-assign them:

- **PostgreSQL ports** start from 5433
- **pgAdmin ports** start from 8081
- Ports are deterministically assigned based on audit name

## Tips

1. **Use descriptive audit names** (e.g., `client_name`, `project_name`)
2. **Keep track of your port assignments** to avoid conflicts
3. **Use the management scripts** for easy environment control
4. **Review the generated config files** before starting environments
5. **Consider using different passwords** for each environment 