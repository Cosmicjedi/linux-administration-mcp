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
- **Runtime Credentials** - Pass SSH credentials at runtime (no Docker secrets required)

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

### Step 3: Create Custom Catalog
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
        required: false
        description: "Directory for storing audit logs (optional, defaults to /tmp/linux-admin-logs)"
    volumes:
      - host: "C:\\logs:/mnt/logs"
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

### Step 4: Update Registry
```bash
# Edit registry file to add the server
cat >> ~/.docker/mcp/registry.yaml << 'EOF'
  linux-admin:
    ref: ""
EOF
```

### Step 5: Configure Claude Desktop

Find your Claude Desktop config file:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

Edit the file to add the custom catalog:

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

**Configuration Notes:**
- The volume mount `-v YOUR_HOST_PATH:/mnt/logs` is optional but recommended for persistent logs
- If no log directory is specified, logs will be stored in `/tmp/linux-admin-logs` inside the container
- Replace `YourUsername` with your actual username

### Step 6: Create Your Log Directory (Optional but Recommended)

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

### Step 7: Restart Claude Desktop
1. Quit Claude Desktop completely
2. Start Claude Desktop again
3. The Linux Administration tools should now be available!

## Authentication Methods

The server supports multiple authentication methods, with credentials provided at runtime:

### 1. Password Authentication
Pass the password directly in the tool call:
```
"Connect to server.example.com with username admin and password mypassword"
```

### 2. SSH Key Authentication
Specify a key path in the tool call:
```
"Connect to server.example.com using key at /path/to/key"
```

### 3. Default SSH Keys
If no credentials are provided, the server will attempt to use:
- System default SSH keys (~/.ssh/id_rsa, ~/.ssh/id_ed25519, etc.)
- Any key configured in SSH_KEY_PATH environment variable (optional)

### 4. Integration with Secret Management
Designed to work with external secret management systems. Your application can:
1. Retrieve credentials from a secret server
2. Pass them to the Linux Admin tools at runtime
3. Never store credentials permanently

## Log File Organization

The MCP server organizes logs with the following structure:
- **Format**: `hostname-MMDDYYYY.json` (e.g., `webserver-01012025.json`)
- **Rotation**: Daily - new log file created each day for each host
- **Location**: Configured LOG_DIR directory (defaults to `/tmp/linux-admin-logs`)
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
"Test SSH connection to server 192.168.1.100 with username admin and password secret123"
```

### System Diagnostics
```
"Connect to webserver.example.com as root with my SSH key at /home/user/.ssh/web_key and check if it's running properly"
"Run full diagnostics on database server at 10.0.0.5 using password authentication"
```

### Service Management
```
"Check the nginx service status on production server (use admin account with password)"
"Restart MySQL on database.local using root account"
"Stop and disable Apache on web-server-01"
```

### Package Installation
```
"Install htop on server1.example.com (connect as admin)"
"Install docker on ubuntu-server.local using sudo user"
```

### Security Audit
```
"Check for security issues on my public-facing server (use key authentication)"
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
    SSH (with runtime credentials)
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
- **No Hardcoded Credentials**: Server never stores credentials
- **Runtime Only**: Credentials are passed at tool invocation time
- **Multiple Methods**: Supports passwords, SSH keys, and system defaults
- **Secret Management Ready**: Designed to integrate with external secret servers

### Audit Logging
- **Complete Trail**: Every command is logged with timestamp, user, and outcome
- **JSON Format**: Structured logs for easy parsing and analysis
- **Daily Rotation**: Automatic daily log rotation per hostname
- **Configurable Location**: Choose your own secure log directory
- **Compliance Ready**: Suitable for regulatory compliance requirements

### Best Practices
1. Use SSH keys instead of passwords when possible
2. Integrate with a proper secret management system
3. Regularly rotate SSH keys and passwords
4. Review audit logs periodically
5. Use specific user accounts, not always root
6. Implement network segmentation for sensitive servers
7. Enable firewall rules to restrict SSH access
8. Use jump hosts for accessing production servers
9. Set up log rotation and archiving for long-term storage

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

### SSH Connection Issues
- Verify SSH service is running on target server
- Check firewall allows SSH port (usually 22)
- Confirm correct hostname/IP and credentials
- Test manual SSH connection first
- Check if password authentication is enabled on the server

### Tools Not Appearing in Claude
- Verify Docker image built successfully: `docker images`
- Check catalog file syntax: `cat ~/.docker/mcp/catalogs/custom.yaml`
- Ensure Claude Desktop config has custom catalog path
- Restart Claude Desktop completely

### Logging Issues
- Check if log directory exists and is writable
- Verify volume mount in Docker configuration
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
3. Include password and key_path parameters for authentication
4. Use single-line docstrings only
5. Return formatted strings with status indicators
6. Update catalog with new tool name
7. Rebuild Docker image

### Testing Locally
```bash
# Run server directly with optional log directory
export LOG_DIR="/tmp/test-logs"  # Optional
python linux_admin_server.py

# Test MCP protocol
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | python linux_admin_server.py
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `LOG_DIR` | No | `/tmp/linux-admin-logs` | Directory path for storing audit logs |
| `SSH_KEY_PATH` | No | None | Optional default SSH private key path |
| `SSH_KNOWN_HOSTS` | No | None | Optional path to known hosts file |
| `SSH_CONFIG_PATH` | No | None | Optional path to SSH config file |

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

### Version 3.0.0 (Latest)
- **Breaking Change**: Removed requirement for Docker secrets
- **New**: All SSH credentials can now be provided at runtime
- **New**: LOG_DIR is now optional with fallback to `/tmp/linux-admin-logs`
- **Improved**: Better authentication flexibility with multiple methods
- **Enhanced**: Designed for integration with external secret management systems
- **Fixed**: Server starts successfully without any required environment variables

### Version 2.0.0
- LOG_DIR required as environment variable
- Added hostname-based log file organization
- Implemented daily log rotation per hostname
- Added `get_log_status` tool
- Enhanced `view_command_logs` with filtering

### Version 1.0.0
- Initial release with core SSH management features
- Basic logging to fixed directory
