# Linux Administration MCP Server

A Model Context Protocol (MCP) server that provides advanced SSH-based Linux server management with comprehensive command logging and audit trails.

## Overview

This MCP server enables AI assistants (like Claude) to connect to remote Linux servers via SSH, diagnose issues, execute commands, and perform administrative tasks while maintaining a complete audit log of all actions. It's designed for system administrators who want to leverage AI for server management while maintaining security and compliance through comprehensive logging.

## Features

### 🔧 Core Capabilities
- **SSH Connection Management** - Test and establish secure connections to remote servers
- **Command Execution** - Run any command on remote servers with full output capture
- **System Diagnostics** - Comprehensive health checks including CPU, memory, disk, and network
- **Service Management** - Start, stop, restart, enable, or disable services
- **Log Analysis** - Search and analyze log files on remote servers
- **Network Diagnostics** - Test connectivity and troubleshoot network issues
- **Package Management** - Install software using the appropriate package manager
- **Security Auditing** - Check user access, open ports, firewall rules, and security configurations
- **Audit Trail** - Complete logging of all commands with hostname-based daily rotation

### 📊 Available Tools

1. **`ssh_connect_test`** - Test SSH connectivity and retrieve basic system information
2. **`ssh_execute`** - Execute any command on a remote server with full output capture
3. **`ssh_diagnose_system`** - Run comprehensive system diagnostics
4. **`ssh_check_service`** - Check the status and logs of specific services
5. **`ssh_manage_service`** - Start, stop, restart, enable, or disable services
6. **`ssh_analyze_logs`** - Analyze and search through log files
7. **`ssh_network_diagnostics`** - Run network diagnostics and connectivity tests
8. **`ssh_install_package`** - Install packages using the appropriate package manager
9. **`ssh_check_security`** - Perform security audits
10. **`view_command_logs`** - View the audit log of all executed commands
11. **`get_log_status`** - Get current logging configuration and statistics

## Prerequisites

- Docker Desktop with MCP Toolkit enabled
- Docker MCP CLI plugin (`docker mcp` command)
- SSH access to target Linux servers
- SSH keys or passwords for authentication
- A directory for storing audit logs

## Installation

### Step 1: Clone the Repository
```bash
git clone https://github.com/Cosmicjedi/linux-administration-mcp.git
cd linux-administration-mcp
```

### Step 2: Build Docker Image
```bash
docker build -t linux-admin-mcp-server .
```

### Step 3: Set Up SSH Authentication (Optional)
```bash
# For SSH key authentication
docker mcp secret set SSH_PRIVATE_KEY="$(cat ~/.ssh/id_rsa)"

# For password authentication
docker mcp secret set SSH_PASSWORD="your-password"

# Verify secrets
docker mcp secret list
```

### Step 4: Create Custom Catalog
```bash
# Create catalogs directory if it doesn't exist
mkdir -p ~/.docker/mcp/catalogs

# Create custom.yaml
cat > ~/.docker/mcp/catalogs/custom.yaml << 'EOF'
version: 2
name: custom
displayName: Custom MCP Servers
registry:
  linux-admin:
    description: "Advanced SSH-based Linux server management with audit logging"
    title: "Linux Administration"
    type: server
    dateAdded: "2025-01-01T00:00:00Z"
    image: linux-admin-mcp-server:latest
    ref: ""
    readme: ""
    toolsUrl: ""
    source: ""
    upstream: ""
    icon: ""
    tools:
      - name: ssh_connect_test
      - name: ssh_execute
      - name: ssh_diagnose_system
      - name: ssh_check_service
      - name: ssh_manage_service
      - name: ssh_analyze_logs
      - name: ssh_network_diagnostics
      - name: ssh_install_package
      - name: ssh_check_security
      - name: view_command_logs
      - name: get_log_status
    environment:
      - name: LOG_DIR
        value: "/mnt/logs"
        required: true
        description: "Directory for storing audit logs (required)"
    volumes:
      - host: "C:\\logs:/mnt/logs"
    secrets:
      - name: SSH_PRIVATE_KEY
        env: SSH_KEY_PATH
        example: "/home/mcpuser/.ssh/id_rsa"
      - name: SSH_PASSWORD
        env: DEFAULT_SSH_PASSWORD
        example: "password123"
    metadata:
      category: monitoring
      tags:
        - linux
        - ssh
        - administration
        - monitoring
        - security
        - audit
      license: MIT
      owner: local
EOF
```

### Step 5: Update Registry
```bash
# Edit registry file to add the server
cat >> ~/.docker/mcp/registry.yaml << 'EOF'
  linux-admin:
    ref: ""
EOF
```

### Step 6: Configure Claude Desktop

Find your Claude Desktop config file:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

Edit the file to add the custom catalog and configure your log directory:

#### Windows Example:
```json
{
  "mcpServers": {
    "mcp-toolkit-gateway": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", "C:\\Users\\YourUsername\\.docker\\mcp:/mcp",
        "-v", "C:\\logs:/mnt/logs",
        "-e", "LOG_DIR=/mnt/logs",
        "docker/mcp-gateway",
        "--catalog=/mcp/catalogs/docker-mcp.yaml",
        "--catalog=/mcp/catalogs/custom.yaml",
        "--config=/mcp/config.yaml",
        "--registry=/mcp/registry.yaml",
        "--tools-config=/mcp/tools.yaml",
        "--transport=stdio"
      ]
    }
  }
}
```

#### macOS/Linux Example:
```json
{
  "mcpServers": {
    "mcp-toolkit-gateway": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", "/Users/YourUsername/.docker/mcp:/mcp",
        "-v", "/var/log/linux-admin:/mnt/logs",
        "-e", "LOG_DIR=/mnt/logs",
        "docker/mcp-gateway",
        "--catalog=/mcp/catalogs/docker-mcp.yaml",
        "--catalog=/mcp/catalogs/custom.yaml",
        "--config=/mcp/config.yaml",
        "--registry=/mcp/registry.yaml",
        "--tools-config=/mcp/tools.yaml",
        "--transport=stdio"
      ]
    }
  }
}
```

**Important Configuration Notes:**
- The `-e LOG_DIR=/mnt/logs` environment variable is **REQUIRED**
- The volume mount `-v YOUR_HOST_PATH:/mnt/logs` maps your chosen log directory
- Replace `YourUsername` with your actual username
- You can choose any directory on your host system for logs

### Step 7: Create Your Log Directory

Choose and create your preferred log directory:

#### Windows:
```bash
# Option 1: Use C:\logs
mkdir C:\logs

# Option 2: Use a user-specific directory
mkdir C:\Users\%USERNAME%\Documents\LinuxAdminLogs
```

#### macOS/Linux:
```bash
# Option 1: Use system log directory (requires sudo)
sudo mkdir -p /var/log/linux-admin
sudo chmod 755 /var/log/linux-admin

# Option 2: Use home directory
mkdir -p ~/linux-admin-logs
```

### Step 8: Restart Claude Desktop
1. Quit Claude Desktop completely
2. Start Claude Desktop again
3. The Linux Administration tools should now be available!

## Log File Organization

The MCP server organizes logs with the following structure:
- **Format**: `hostname-MMDDYYYY.json` (e.g., `webserver-01012025.json`)
- **Rotation**: Daily - new log file created each day for each host
- **Location**: Your configured LOG_DIR directory
- **Content**: JSON Lines format with all command execution details

### Log File Naming Examples:
- `production-server-01152025.json` - Commands run on production-server on Jan 15, 2025
- `database_local-01152025.json` - Commands run on database.local on Jan 15, 2025
- `192_168_1_100-01152025.json` - Commands run on IP 192.168.1.100 on Jan 15, 2025

Note: Special characters in hostnames are replaced with underscores for filesystem compatibility.

## Usage Examples

In Claude Desktop, you can use natural language commands:

### Basic Connection Test
```
"Test SSH connection to server 192.168.1.100 with username admin"
```

### System Diagnostics
```
"Connect to webserver.example.com and check if it's running properly"
"Run full diagnostics on my database server at 10.0.0.5"
```

### Service Management
```
"Check the nginx service status on production server"
"Restart MySQL on database.local"
"Stop and disable Apache on web-server-01"
```

### Package Installation
```
"Install htop on server1.example.com"
"Install docker on ubuntu-server.local"
```

### Security Audit
```
"Check for security issues on my public-facing server"
"Show me failed login attempts on auth-server"
"List all users with sudo access on prod-server"
```

### Log Analysis
```
"Find errors in the Apache logs on webserver"
"Search for 'connection refused' in system logs on db-server"
"Show me the last 100 lines of nginx error log"
```

### Network Diagnostics
```
"Test connectivity from web-server to database-server"
"Check if port 443 is open on api.example.com"
"Run traceroute from server1 to google.com"
```

### Audit Trail Review
```
"Show me all commands executed on production-server"
"What commands were run yesterday on any server?"
"Show failed commands from webserver for the last week"
"Get the current log status"
```

## Architecture

```
Claude Desktop
      ↓
MCP Gateway (Docker)
      ↓
Linux Admin MCP Server (Container)
      ↓
    SSH
      ↓
Remote Linux Servers
      ↓
Audit Logs (JSON) → Your Configured Directory
                     ├── server1-01152025.json
                     ├── server2-01152025.json
                     └── server3-01162025.json
```

## Security Considerations

### Authentication
- **SSH Keys**: Recommended for production use
- **Passwords**: Stored securely in Docker Desktop secrets
- **No Hardcoding**: Never hardcode credentials in the server code

### Audit Logging
- **Complete Trail**: Every command is logged with timestamp, user, and outcome
- **JSON Format**: Structured logs for easy parsing and analysis
- **Daily Rotation**: Automatic daily log rotation per hostname
- **Configurable Location**: Choose your own secure log directory
- **Compliance Ready**: Suitable for regulatory compliance requirements

### Best Practices
1. Use SSH keys instead of passwords
2. Regularly rotate SSH keys
3. Review audit logs periodically
4. Use specific user accounts, not always root
5. Implement network segmentation for sensitive servers
6. Enable firewall rules to restrict SSH access
7. Use jump hosts for accessing production servers
8. Set up log rotation and archiving for long-term storage

## Log Format

Logs are stored in JSON Lines format (one JSON object per line):
```json
{
  "timestamp": "2025-01-15T12:00:00Z",
  "hostname": "server.example.com",
  "user": "admin",
  "command": "systemctl restart nginx",
  "output": "...",
  "error": "",
  "success": true
}
```

## Troubleshooting

### LOG_DIR Environment Variable Not Set
- **Error**: "ERROR: LOG_DIR environment variable is required"
- **Solution**: Ensure `-e LOG_DIR=/mnt/logs` is in your Claude Desktop config

### SSH Connection Issues
- Verify SSH service is running on target server
- Check firewall allows SSH port (usually 22)
- Confirm correct hostname/IP and credentials
- Test manual SSH connection first

### Tools Not Appearing in Claude
- Verify Docker image built successfully: `docker images`
- Check catalog file syntax: `cat ~/.docker/mcp/catalogs/custom.yaml`
- Ensure Claude Desktop config has custom catalog path
- Restart Claude Desktop completely

### Logging Issues
- Verify LOG_DIR is set correctly
- Check volume mount in Docker configuration
- Ensure sufficient disk space for logs
- Review Docker container logs: `docker logs [container_id]`
- Use `get_log_status` tool to check configuration

### Permission Denied Errors
- Verify user has sudo privileges on target server
- Check SSH key permissions (should be 600)
- Ensure service management commands are run as root or with sudo
- Check log directory permissions on host system

## Development

### Adding New Tools

1. Edit `linux_admin_server.py`
2. Add new function with `@mcp.tool()` decorator
3. Use single-line docstrings only
4. Return formatted strings with status indicators
5. Update catalog with new tool name
6. Rebuild Docker image

### Testing Locally
```bash
# Set environment variables
export LOG_DIR="/tmp/test-logs"
export SSH_KEY_PATH="/path/to/key"

# Run server directly
python linux_admin_server.py

# Test MCP protocol
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | python linux_admin_server.py
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `LOG_DIR` | **Yes** | None | Directory path for storing audit logs |
| `SSH_KEY_PATH` | No | `/home/mcpuser/.ssh/id_rsa` | Path to SSH private key |
| `SSH_KNOWN_HOSTS` | No | `/home/mcpuser/.ssh/known_hosts` | Path to known hosts file |
| `SSH_CONFIG_PATH` | No | `/home/mcpuser/.ssh/config` | Path to SSH config file |

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Update documentation
5. Submit a pull request

## License

MIT License - See LICENSE file for details

## Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing issues for solutions
- Provide detailed logs when reporting problems

## Acknowledgments

- Built for the MCP (Model Context Protocol) ecosystem
- Designed for use with Claude Desktop
- Uses asyncssh for secure SSH connections
- Inspired by DevOps automation needs

## Changelog

### Version 2.0.0 (Latest)
- **Breaking Change**: LOG_DIR is now a required environment variable
- Added hostname-based log file organization (hostname-MMDDYYYY.json)
- Implemented daily log rotation per hostname
- Added `get_log_status` tool for monitoring logging configuration
- Improved `view_command_logs` to support hostname filtering
- Enhanced log file naming with hostname sanitization

### Version 1.0.0
- Initial release with core SSH management features
- Basic logging to fixed directory
