# Linux Administration MCP Server - Claude Integration Guide

## Overview
This MCP server enables Claude to perform advanced Linux system administration tasks via SSH. It provides comprehensive diagnostic, management, and security capabilities with full audit logging.

## Key Capabilities

### 1. Connection Management
- Test SSH connectivity before executing commands
- Support for both password and key-based authentication
- Configurable ports and connection parameters

### 2. System Diagnostics
- Comprehensive health checks (CPU, memory, disk, network)
- Service status monitoring
- Log analysis with search capabilities
- Network connectivity testing

### 3. System Management
- Execute arbitrary commands with full output capture
- Service management (start/stop/restart/enable/disable)
- Package installation with automatic package manager detection
- Configuration file viewing and editing

### 4. Security Auditing
- User access reviews
- Open port scanning
- Firewall rule inspection
- Failed login attempt monitoring
- SUID file detection

### 5. Audit Logging
- Every command is logged with timestamp, user, and outcome
- Logs stored in JSON format for easy parsing
- Searchable audit trail
- Compliance-ready logging

## Usage Patterns

### Initial Connection
Always start with `ssh_connect_test` to verify connectivity:
```
"Test connection to server 192.168.1.100 with username admin"
```

### Diagnostic Workflow
1. Run `ssh_diagnose_system` for overall health
2. Check specific services with `ssh_check_service`
3. Analyze logs with `ssh_analyze_logs`
4. Review network with `ssh_network_diagnostics`

### Problem Resolution
1. Identify the issue using diagnostics
2. Execute fix with `ssh_execute` or `ssh_manage_service`
3. Verify resolution
4. Document in audit log

### Security Audit
1. Run `ssh_check_security` for comprehensive review
2. Check specific concerns (users, ports, firewall)
3. Review audit logs with `view_command_logs`
4. Recommend remediation steps

## Best Practices

### Authentication
- Prefer SSH keys over passwords
- Store keys securely in Docker secrets
- Use specific user accounts, not always root

### Command Execution
- Always validate commands before execution
- Use appropriate timeouts for long-running commands
- Check command success/failure status

### Logging
- Review logs regularly
- Set up log rotation for long-term storage
- Filter logs by hostname or command when reviewing

### Security
- Minimize use of root access
- Verify commands won't cause system damage
- Document all changes in audit log
- Regular security audits

## Common Issues and Solutions

### Connection Refused
- Check SSH service is running
- Verify firewall allows SSH port
- Confirm correct hostname/IP

### Permission Denied
- Verify username and password/key
- Check SSH configuration allows user
- Ensure key permissions are 600

### Command Timeout
- Network connectivity issues
- Command taking too long
- Adjust timeout if needed

### Service Management Failures
- Check systemd vs init system
- Verify service name is correct
- Ensure sufficient permissions

## Advanced Features

### Custom SSH Configurations
Mount SSH config file to `/home/mcpuser/.ssh/config` for:
- Host aliases
- ProxyJump configurations
- Custom connection parameters

### Batch Operations
Execute commands on multiple servers:
```
"Check disk space on servers web1, web2, and web3"
```

### Scheduled Diagnostics
Combine with other tools for regular health checks:
```
"Run daily diagnostics on production servers and alert on issues"
```

### Compliance Reporting
Use audit logs for compliance:
```
"Generate report of all root commands executed this week"
```

## Integration Tips

### With Monitoring Systems
- Parse diagnostic output for metrics
- Create alerts based on thresholds
- Feed data to monitoring dashboards

### With Ticketing Systems
- Auto-create tickets for issues found
- Update tickets with resolution steps
- Attach audit logs to tickets

### With Configuration Management
- Verify configuration deployments
- Test service changes
- Validate system state

## Performance Considerations

- SSH connections have overhead; reuse when possible
- Large log files may take time to transfer
- Network diagnostics can impact bandwidth
- Package installations may require significant time

## Limitations

- Cannot perform GUI operations
- Some commands may require TTY allocation
- Real-time streaming output not supported
- Binary file transfers not implemented
- Maximum command execution timeout of 30 seconds

## Security Notes

- All commands are logged and cannot be deleted
- Passwords are not logged but commands are
- SSH keys should be regularly rotated
- Review audit logs for suspicious activity
- Implement principle of least privilege

## Tool Reference

### ssh_connect_test
- **Purpose**: Test connectivity and get basic system info
- **Parameters**: hostname, username, port, password, key_path
- **Returns**: System information or error message

### ssh_execute
- **Purpose**: Execute any command on remote server
- **Parameters**: hostname, command, username, port, password, key_path
- **Returns**: Command output or error message

### ssh_diagnose_system
- **Purpose**: Comprehensive system health check
- **Parameters**: hostname, username, port, password, key_path
- **Returns**: Detailed diagnostic report

### ssh_check_service
- **Purpose**: Check specific service status
- **Parameters**: hostname, service_name, username, port, password, key_path
- **Returns**: Service status and recent logs

### ssh_manage_service
- **Purpose**: Control service state
- **Parameters**: hostname, service_name, action, username, port, password, key_path
- **Returns**: Action result and new status

### ssh_analyze_logs
- **Purpose**: Search and analyze log files
- **Parameters**: hostname, log_path, search_term, lines, username, port, password, key_path
- **Returns**: Matching log entries

### ssh_network_diagnostics
- **Purpose**: Network connectivity testing
- **Parameters**: hostname, target_host, username, port, password, key_path
- **Returns**: Network test results

### ssh_install_package
- **Purpose**: Install software packages
- **Parameters**: hostname, package_name, username, port, password, key_path
- **Returns**: Installation result

### ssh_check_security
- **Purpose**: Security configuration audit
- **Parameters**: hostname, username, port, password, key_path
- **Returns**: Security analysis report

### view_command_logs
- **Purpose**: Review audit logs
- **Parameters**: date, hostname_filter, command_filter
- **Returns**: Filtered log entries