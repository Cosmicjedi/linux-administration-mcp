#!/usr/bin/env python3
"""
Linux Administration MCP Server - Advanced SSH-based Linux server management with comprehensive logging
Modified to work without required SSH secrets - credentials can be provided at runtime
Fixed async/await issues with asyncssh connections
"""
import os
import sys
import logging
import json
import asyncio
import subprocess
from datetime import datetime, timezone
from pathlib import Path
import asyncssh
import aiofiles
from mcp.server.fastmcp import FastMCP

# Configure logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("linux-admin-server")

# Initialize MCP server
mcp = FastMCP("linux-admin")

# Configuration - LOG_DIR is now OPTIONAL with fallback
LOG_DIR = os.environ.get("LOG_DIR", "/tmp/linux-admin-logs")
LOG_DIR = Path(LOG_DIR)

# Create log directory if it doesn't exist
try:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"Log directory configured: {LOG_DIR}")
except Exception as e:
    logger.warning(f"Could not create log directory {LOG_DIR}: {e}")
    # Use temp directory as fallback
    LOG_DIR = Path("/tmp/linux-admin-logs")
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"Using fallback log directory: {LOG_DIR}")

# SSH Configuration - all optional with defaults
SSH_KEY_PATH = os.environ.get("SSH_KEY_PATH", "")  # Empty string if not set
SSH_KNOWN_HOSTS = os.environ.get("SSH_KNOWN_HOSTS", "")  # Empty string if not set
SSH_CONFIG_PATH = os.environ.get("SSH_CONFIG_PATH", "")  # Empty string if not set
DEFAULT_SSH_PORT = 22
DEFAULT_SSH_TIMEOUT = 30

# Log if SSH key paths are configured
if SSH_KEY_PATH:
    logger.info(f"SSH key path configured: {SSH_KEY_PATH}")
else:
    logger.info("No default SSH key path configured - credentials must be provided at runtime")

# === UTILITY FUNCTIONS ===

def sanitize_hostname(hostname: str) -> str:
    """Sanitize hostname for use in filename"""
    # Replace invalid filename characters
    invalid_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
    sanitized = hostname
    for char in invalid_chars:
        sanitized = sanitized.replace(char, '_')
    return sanitized

async def log_command(hostname: str, command: str, output: str, error: str = "", user: str = ""):
    """Log command execution to hostname-specific file with daily rotation"""
    timestamp = datetime.now(timezone.utc).isoformat()
    log_entry = {
        "timestamp": timestamp,
        "hostname": hostname,
        "user": user,
        "command": command,
        "output": output[:10000] if output else "",  # Limit output size
        "error": error[:5000] if error else "",
        "success": not bool(error)
    }
    
    # Create log filename with hostname and date (hostname-MMDDYYYY.json)
    log_date = datetime.now().strftime("%m%d%Y")
    sanitized_hostname = sanitize_hostname(hostname)
    log_file = LOG_DIR / f"{sanitized_hostname}-{log_date}.json"
    
    try:
        # Create log directory if it doesn't exist
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        
        # Append to JSON lines format
        async with aiofiles.open(log_file, mode='a') as f:
            await f.write(json.dumps(log_entry) + "\n")
        logger.info(f"Command logged to {log_file}")
    except Exception as e:
        logger.error(f"Failed to write log: {e}")

async def establish_ssh_connection(hostname: str, port: int, username: str, password: str = "", key_path: str = ""):
    """Establish SSH connection to remote host"""
    try:
        connect_args = {
            'host': hostname,
            'port': port,
            'username': username,
            'known_hosts': None  # Disable host key checking for flexibility
        }
        
        # Authentication priority:
        # 1. Password if provided
        # 2. Specific key path if provided
        # 3. Default key path if it exists
        # 4. Let asyncssh try default locations (~/.ssh/id_*)
        
        if password:
            logger.info(f"Using password authentication for {username}@{hostname}")
            connect_args['password'] = password
        elif key_path and os.path.exists(key_path):
            logger.info(f"Using SSH key from {key_path}")
            connect_args['client_keys'] = [key_path]
        elif SSH_KEY_PATH and os.path.exists(SSH_KEY_PATH):
            logger.info(f"Using default SSH key from {SSH_KEY_PATH}")
            connect_args['client_keys'] = [SSH_KEY_PATH]
        else:
            logger.info(f"Attempting SSH connection with system defaults for {username}@{hostname}")
            # asyncssh will try default key locations
        
        # Add known_hosts if configured and exists
        if SSH_KNOWN_HOSTS and os.path.exists(SSH_KNOWN_HOSTS):
            connect_args['known_hosts'] = SSH_KNOWN_HOSTS
        
        # Fix: Properly await the connection
        conn = await asyncssh.connect(**connect_args)
        return conn
    except Exception as e:
        raise Exception(f"SSH connection failed: {str(e)}")

async def execute_remote_command(conn, command: str):
    """Execute command on remote host"""
    try:
        result = await conn.run(command, timeout=DEFAULT_SSH_TIMEOUT)
        return result.stdout, result.stderr, result.exit_status
    except asyncio.TimeoutError:
        return "", "Command execution timed out", -1
    except Exception as e:
        return "", str(e), -1

# === MCP TOOLS ===

@mcp.tool()
async def ssh_connect_test(hostname: str = "", username: str = "root", port: str = "22", password: str = "", key_path: str = "") -> str:
    """Test SSH connection to a remote server and return system information.
    
    Authentication methods (in order of priority):
    1. Password if provided
    2. Key path if provided
    3. System default SSH keys
    """
    logger.info(f"Testing SSH connection to {hostname}")
    
    if not hostname.strip():
        return "❌ Error: Hostname or IP address is required"
    
    if not username.strip():
        username = "root"
    
    try:
        port_int = int(port) if port.strip() else DEFAULT_SSH_PORT
        
        conn = await establish_ssh_connection(hostname, port_int, username, password, key_path)
        
        # Get basic system info
        commands = [
            "hostname -f",
            "uname -a",
            "cat /etc/os-release | head -3",
            "uptime",
            "df -h / | tail -1"
        ]
        
        info_lines = [f"✅ Successfully connected to {hostname}"]
        info_lines.append("=" * 50)
        
        for cmd in commands:
            stdout, stderr, exit_status = await execute_remote_command(conn, cmd)
            if exit_status == 0 and stdout:
                info_lines.append(stdout.strip())
        
        conn.close()
        
        result = "\n".join(info_lines)
        await log_command(hostname, "ssh_connect_test", result, "", username)
        return result
        
    except Exception as e:
        error_msg = f"❌ Connection failed: {str(e)}"
        await log_command(hostname, "ssh_connect_test", "", error_msg, username)
        return error_msg

@mcp.tool()
async def ssh_execute(hostname: str = "", command: str = "", username: str = "root", port: str = "22", password: str = "", key_path: str = "") -> str:
    """Execute a single command on a remote server via SSH.
    
    Authentication methods (in order of priority):
    1. Password if provided
    2. Key path if provided
    3. System default SSH keys
    """
    logger.info(f"Executing command on {hostname}: {command}")
    
    if not hostname.strip():
        return "❌ Error: Hostname or IP address is required"
    
    if not command.strip():
        return "❌ Error: Command is required"
    
    if not username.strip():
        username = "root"
    
    try:
        port_int = int(port) if port.strip() else DEFAULT_SSH_PORT
        
        conn = await establish_ssh_connection(hostname, port_int, username, password, key_path)
        
        stdout, stderr, exit_status = await execute_remote_command(conn, command)
        
        conn.close()
        
        if exit_status == 0:
            result = f"✅ Command executed successfully on {hostname}\n\nOutput:\n{stdout}"
            if stderr:
                result += f"\n\nWarnings:\n{stderr}"
        else:
            result = f"❌ Command failed with exit code {exit_status}\n\nError:\n{stderr}\n\nOutput:\n{stdout}"
        
        await log_command(hostname, command, stdout, stderr, username)
        return result
        
    except Exception as e:
        error_msg = f"❌ Error: {str(e)}"
        await log_command(hostname, command, "", error_msg, username)
        return error_msg

@mcp.tool()
async def ssh_diagnose_system(hostname: str = "", username: str = "root", port: str = "22", password: str = "", key_path: str = "") -> str:
    """Run comprehensive system diagnostics on a remote server."""
    logger.info(f"Running diagnostics on {hostname}")
    
    if not hostname.strip():
        return "❌ Error: Hostname or IP address is required"
    
    if not username.strip():
        username = "root"
    
    try:
        port_int = int(port) if port.strip() else DEFAULT_SSH_PORT
        
        conn = await establish_ssh_connection(hostname, port_int, username, password, key_path)
        
        diagnostics = []
        diagnostics.append(f"📊 System Diagnostics for {hostname}")
        diagnostics.append("=" * 60)
        
        # System information
        commands = {
            "🖥️ SYSTEM INFO": "uname -a && hostname -f",
            "⏱️ UPTIME & LOAD": "uptime",
            "💾 MEMORY USAGE": "free -h && echo '---' && cat /proc/meminfo | grep -E 'MemTotal|MemFree|MemAvailable|Cached|SwapTotal|SwapFree'",
            "💿 DISK USAGE": "df -h && echo '---' && df -i",
            "🔄 TOP PROCESSES": "ps aux --sort=-%cpu | head -10",
            "📡 NETWORK STATUS": "ip a | grep -E 'inet |state' && echo '---' && ss -tulpn | head -20",
            "🔥 FIREWALL STATUS": "iptables -L -n | head -30 2>/dev/null || echo 'No iptables rules or permission denied'",
            "📋 RECENT LOGS": "journalctl -p err -n 20 --no-pager 2>/dev/null || dmesg | tail -20",
            "🔧 SERVICE STATUS": "systemctl list-units --state=failed 2>/dev/null || service --status-all 2>/dev/null | grep -E '\\[\\-\\]'",
            "🌡️ SYSTEM RESOURCES": "iostat -x 1 2 2>/dev/null | tail -20 || vmstat 1 2"
        }
        
        for title, cmd in commands.items():
            diagnostics.append(f"\n{title}")
            diagnostics.append("-" * 40)
            stdout, stderr, exit_status = await execute_remote_command(conn, cmd)
            if stdout:
                diagnostics.append(stdout.strip())
            if stderr and exit_status != 0:
                diagnostics.append(f"Error: {stderr.strip()}")
        
        conn.close()
        
        result = "\n".join(diagnostics)
        await log_command(hostname, "ssh_diagnose_system", result, "", username)
        return result
        
    except Exception as e:
        error_msg = f"❌ Error: {str(e)}"
        await log_command(hostname, "ssh_diagnose_system", "", error_msg, username)
        return error_msg

@mcp.tool()
async def ssh_check_service(hostname: str = "", service_name: str = "", username: str = "root", port: str = "22", password: str = "", key_path: str = "") -> str:
    """Check the status of a specific service on a remote server."""
    logger.info(f"Checking service {service_name} on {hostname}")
    
    if not hostname.strip():
        return "❌ Error: Hostname or IP address is required"
    
    if not service_name.strip():
        return "❌ Error: Service name is required"
    
    if not username.strip():
        username = "root"
    
    try:
        port_int = int(port) if port.strip() else DEFAULT_SSH_PORT
        
        conn = await establish_ssh_connection(hostname, port_int, username, password, key_path)
        
        results = [f"🔍 Service Check: {service_name} on {hostname}"]
        results.append("=" * 50)
        
        # Check if systemctl is available
        stdout, stderr, exit_status = await execute_remote_command(conn, "which systemctl")
        
        if exit_status == 0:
            # Use systemctl for modern systems
            commands = [
                f"systemctl status {service_name}",
                f"systemctl is-enabled {service_name} 2>/dev/null",
                f"journalctl -u {service_name} -n 20 --no-pager"
            ]
        else:
            # Fall back to service command for older systems
            commands = [
                f"service {service_name} status",
                f"chkconfig --list {service_name} 2>/dev/null || update-rc.d -n {service_name} 2>/dev/null",
                f"tail -50 /var/log/{service_name}.log 2>/dev/null || tail -50 /var/log/syslog | grep {service_name}"
            ]
        
        for cmd in commands:
            stdout, stderr, exit_status = await execute_remote_command(conn, cmd)
            if stdout:
                results.append(stdout.strip())
                results.append("-" * 30)
        
        conn.close()
        
        result = "\n".join(results)
        await log_command(hostname, f"check_service:{service_name}", result, "", username)
        return result
        
    except Exception as e:
        error_msg = f"❌ Error: {str(e)}"
        await log_command(hostname, f"check_service:{service_name}", "", error_msg, username)
        return error_msg

@mcp.tool()
async def ssh_manage_service(hostname: str = "", service_name: str = "", action: str = "", username: str = "root", port: str = "22", password: str = "", key_path: str = "") -> str:
    """Manage a service on a remote server (start/stop/restart/enable/disable)."""
    logger.info(f"Managing service {service_name} on {hostname}: {action}")
    
    if not hostname.strip():
        return "❌ Error: Hostname or IP address is required"
    
    if not service_name.strip():
        return "❌ Error: Service name is required"
    
    if not action.strip():
        return "❌ Error: Action is required (start/stop/restart/enable/disable)"
    
    if not username.strip():
        username = "root"
    
    valid_actions = ["start", "stop", "restart", "reload", "enable", "disable"]
    if action.lower() not in valid_actions:
        return f"❌ Error: Invalid action. Must be one of: {', '.join(valid_actions)}"
    
    try:
        port_int = int(port) if port.strip() else DEFAULT_SSH_PORT
        
        conn = await establish_ssh_connection(hostname, port_int, username, password, key_path)
        
        # Check if systemctl is available
        stdout, stderr, exit_status = await execute_remote_command(conn, "which systemctl")
        
        if exit_status == 0:
            command = f"systemctl {action} {service_name}"
        else:
            command = f"service {service_name} {action}"
        
        stdout, stderr, exit_status = await execute_remote_command(conn, command)
        
        # Get current status
        if exit_status == 0:
            status_cmd = f"systemctl status {service_name}" if "systemctl" in command else f"service {service_name} status"
            status_out, _, _ = await execute_remote_command(conn, status_cmd)
            
            result = f"✅ Successfully executed: {action} on {service_name}\n\nCurrent Status:\n{status_out}"
        else:
            result = f"❌ Failed to {action} {service_name}\n\nError:\n{stderr}\n\nOutput:\n{stdout}"
        
        conn.close()
        
        await log_command(hostname, f"manage_service:{service_name}:{action}", stdout, stderr, username)
        return result
        
    except Exception as e:
        error_msg = f"❌ Error: {str(e)}"
        await log_command(hostname, f"manage_service:{service_name}:{action}", "", error_msg, username)
        return error_msg

@mcp.tool()
async def ssh_analyze_logs(hostname: str = "", log_path: str = "", search_term: str = "", lines: str = "50", username: str = "root", port: str = "22", password: str = "", key_path: str = "") -> str:
    """Analyze log files on a remote server with optional search filtering."""
    logger.info(f"Analyzing logs on {hostname}: {log_path}")
    
    if not hostname.strip():
        return "❌ Error: Hostname or IP address is required"
    
    if not username.strip():
        username = "root"
    
    try:
        port_int = int(port) if port.strip() else DEFAULT_SSH_PORT
        lines_int = int(lines) if lines.strip() else 50
        
        conn = await establish_ssh_connection(hostname, port_int, username, password, key_path)
        
        results = [f"📋 Log Analysis on {hostname}"]
        results.append("=" * 50)
        
        if log_path.strip():
            # Analyze specific log file
            if search_term.strip():
                command = f"tail -{lines_int} {log_path} | grep -i '{search_term}' || echo 'No matches found'"
            else:
                command = f"tail -{lines_int} {log_path}"
        else:
            # Analyze system logs
            if search_term.strip():
                command = f"journalctl -n {lines_int} --no-pager | grep -i '{search_term}' 2>/dev/null || dmesg | tail -{lines_int} | grep -i '{search_term}'"
            else:
                command = f"journalctl -n {lines_int} --no-pager 2>/dev/null || dmesg | tail -{lines_int}"
        
        stdout, stderr, exit_status = await execute_remote_command(conn, command)
        
        if stdout:
            results.append(f"Log entries (last {lines_int} lines):")
            if search_term:
                results.append(f"Filter: '{search_term}'")
            results.append("-" * 40)
            results.append(stdout.strip())
        else:
            results.append("No log entries found or permission denied")
        
        conn.close()
        
        result = "\n".join(results)
        await log_command(hostname, f"analyze_logs:{log_path}:{search_term}", result, "", username)
        return result
        
    except Exception as e:
        error_msg = f"❌ Error: {str(e)}"
        await log_command(hostname, f"analyze_logs:{log_path}", "", error_msg, username)
        return error_msg

@mcp.tool()
async def ssh_network_diagnostics(hostname: str = "", target_host: str = "", username: str = "root", port: str = "22", password: str = "", key_path: str = "") -> str:
    """Run network diagnostics from a remote server to check connectivity."""
    logger.info(f"Running network diagnostics from {hostname}")
    
    if not hostname.strip():
        return "❌ Error: Hostname or IP address is required"
    
    if not username.strip():
        username = "root"
    
    try:
        port_int = int(port) if port.strip() else DEFAULT_SSH_PORT
        
        conn = await establish_ssh_connection(hostname, port_int, username, password, key_path)
        
        results = [f"🌐 Network Diagnostics from {hostname}"]
        results.append("=" * 50)
        
        if target_host.strip():
            # Test connectivity to specific host
            tests = {
                f"PING TEST to {target_host}": f"ping -c 4 {target_host}",
                f"DNS RESOLUTION for {target_host}": f"nslookup {target_host} 2>/dev/null || host {target_host} 2>/dev/null || dig {target_host} +short",
                f"TRACEROUTE to {target_host}": f"traceroute -m 10 {target_host} 2>/dev/null || tracepath -m 10 {target_host}",
                f"PORT SCAN common ports on {target_host}": f"nc -zv {target_host} 22 80 443 2>&1 | head -10"
            }
        else:
            # General network diagnostics
            tests = {
                "NETWORK INTERFACES": "ip addr show | grep -E 'state|inet'",
                "ROUTING TABLE": "ip route show || route -n",
                "DNS SERVERS": "cat /etc/resolv.conf | grep nameserver",
                "ACTIVE CONNECTIONS": "ss -tuln | head -20",
                "NETWORK STATISTICS": "netstat -s | head -30 2>/dev/null || ss -s",
                "INTERNET CONNECTIVITY": "ping -c 2 8.8.8.8 && ping -c 2 google.com"
            }
        
        for title, cmd in tests.items():
            results.append(f"\n{title}")
            results.append("-" * 40)
            stdout, stderr, exit_status = await execute_remote_command(conn, cmd)
            if stdout:
                results.append(stdout.strip())
            elif stderr:
                results.append(f"Error: {stderr.strip()}")
        
        conn.close()
        
        result = "\n".join(results)
        await log_command(hostname, f"network_diagnostics:{target_host}", result, "", username)
        return result
        
    except Exception as e:
        error_msg = f"❌ Error: {str(e)}"
        await log_command(hostname, "network_diagnostics", "", error_msg, username)
        return error_msg

@mcp.tool()
async def ssh_install_package(hostname: str = "", package_name: str = "", username: str = "root", port: str = "22", password: str = "", key_path: str = "") -> str:
    """Install a package on a remote server using the appropriate package manager."""
    logger.info(f"Installing package {package_name} on {hostname}")
    
    if not hostname.strip():
        return "❌ Error: Hostname or IP address is required"
    
    if not package_name.strip():
        return "❌ Error: Package name is required"
    
    if not username.strip():
        username = "root"
    
    try:
        port_int = int(port) if port.strip() else DEFAULT_SSH_PORT
        
        conn = await establish_ssh_connection(hostname, port_int, username, password, key_path)
        
        # Detect package manager
        pkg_managers = [
            ("apt-get", "apt-get update && apt-get install -y"),
            ("yum", "yum install -y"),
            ("dnf", "dnf install -y"),
            ("zypper", "zypper install -y"),
            ("pacman", "pacman -Sy --noconfirm")
        ]
        
        pkg_cmd = None
        for pm, install_cmd in pkg_managers:
            stdout, stderr, exit_status = await execute_remote_command(conn, f"which {pm}")
            if exit_status == 0:
                pkg_cmd = f"{install_cmd} {package_name}"
                break
        
        if not pkg_cmd:
            conn.close()
            return "❌ Error: No supported package manager found (apt, yum, dnf, zypper, pacman)"
        
        results = [f"📦 Installing package: {package_name} on {hostname}"]
        results.append("=" * 50)
        
        stdout, stderr, exit_status = await execute_remote_command(conn, pkg_cmd)
        
        if exit_status == 0:
            results.append(f"✅ Successfully installed {package_name}")
            results.append("\nInstallation output:")
            results.append(stdout[-2000:] if len(stdout) > 2000 else stdout)  # Limit output
            
            # Verify installation
            verify_cmd = f"which {package_name} 2>/dev/null || rpm -q {package_name} 2>/dev/null || dpkg -l | grep {package_name}"
            stdout, _, _ = await execute_remote_command(conn, verify_cmd)
            if stdout:
                results.append(f"\nVerification:\n{stdout.strip()}")
        else:
            results.append(f"❌ Failed to install {package_name}")
            results.append(f"Error:\n{stderr}")
        
        conn.close()
        
        result = "\n".join(results)
        await log_command(hostname, f"install_package:{package_name}", stdout, stderr, username)
        return result
        
    except Exception as e:
        error_msg = f"❌ Error: {str(e)}"
        await log_command(hostname, f"install_package:{package_name}", "", error_msg, username)
        return error_msg

@mcp.tool()
async def ssh_check_security(hostname: str = "", username: str = "root", port: str = "22", password: str = "", key_path: str = "") -> str:
    """Run security checks on a remote server including users, sudo, and open ports."""
    logger.info(f"Running security checks on {hostname}")
    
    if not hostname.strip():
        return "❌ Error: Hostname or IP address is required"
    
    if not username.strip():
        username = "root"
    
    try:
        port_int = int(port) if port.strip() else DEFAULT_SSH_PORT
        
        conn = await establish_ssh_connection(hostname, port_int, username, password, key_path)
        
        results = [f"🔒 Security Analysis for {hostname}"]
        results.append("=" * 60)
        
        security_checks = {
            "🔑 SSH CONFIGURATION": "grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|Port)' /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'",
            "👥 USERS WITH SHELL ACCESS": "cat /etc/passwd | grep -E '(/bin/bash|/bin/sh)$' | cut -d: -f1,3,6,7",
            "⚡ SUDO USERS": "grep -E '^[^#]' /etc/sudoers 2>/dev/null | head -20 && ls -la /etc/sudoers.d/ 2>/dev/null",
            "🚪 OPEN PORTS": "ss -tulpn | grep LISTEN || netstat -tulpn | grep LISTEN",
            "🔥 FIREWALL RULES": "iptables -L -n -v | head -50 2>/dev/null || ufw status verbose 2>/dev/null",
            "📅 LAST LOGINS": "last -20",
            "⚠️ FAILED LOGIN ATTEMPTS": "grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -10 || grep 'Failed password' /var/log/secure 2>/dev/null | tail -10",
            "🔄 RECENT SECURITY UPDATES": "grep security /var/log/apt/history.log 2>/dev/null | tail -5 || yum history list | head -10 2>/dev/null",
            "🛡️ SELINUX/APPARMOR STATUS": "getenforce 2>/dev/null || aa-status 2>/dev/null | head -20",
            "📝 SETUID FILES": "find / -perm -4000 -type f 2>/dev/null | head -20"
        }
        
        for title, cmd in security_checks.items():
            results.append(f"\n{title}")
            results.append("-" * 40)
            stdout, stderr, exit_status = await execute_remote_command(conn, cmd)
            if stdout:
                results.append(stdout.strip())
            elif exit_status != 0:
                results.append("Not available or permission denied")
        
        conn.close()
        
        result = "\n".join(results)
        await log_command(hostname, "security_check", result, "", username)
        return result
        
    except Exception as e:
        error_msg = f"❌ Error: {str(e)}"
        await log_command(hostname, "security_check", "", error_msg, username)
        return error_msg

@mcp.tool()
async def view_command_logs(hostname_filter: str = "", date: str = "", command_filter: str = "") -> str:
    """View command execution logs from the logging directory, organized by hostname and date."""
    logger.info(f"Viewing logs for hostname: {hostname_filter}, date: {date}, command: {command_filter}")
    
    try:
        # If specific hostname and date provided, look for that file
        if hostname_filter.strip() and date.strip():
            sanitized_hostname = sanitize_hostname(hostname_filter)
            log_file = LOG_DIR / f"{sanitized_hostname}-{date}.json"
            
            if not log_file.exists():
                return f"📋 No log file found for {hostname_filter} on {date}"
            
            log_files = [log_file]
        else:
            # List all matching log files
            if hostname_filter.strip():
                sanitized_hostname = sanitize_hostname(hostname_filter)
                pattern = f"{sanitized_hostname}-*.json"
            else:
                pattern = "*.json"
            
            log_files = sorted(LOG_DIR.glob(pattern))
            
            if not log_files:
                available = sorted(LOG_DIR.glob("*.json"))
                if available:
                    files_list = "\n".join([f.name for f in available[-10:]])  # Show last 10
                    return f"📋 No matching log files found\n\nAvailable logs (recent):\n{files_list}"
                else:
                    return f"📋 No log files found in {LOG_DIR}"
        
        # Read and filter logs
        all_entries = []
        for log_file in log_files:
            async with aiofiles.open(log_file, mode='r') as f:
                async for line in f:
                    try:
                        entry = json.loads(line.strip())
                        
                        # Apply command filter if specified
                        if command_filter and command_filter.lower() not in entry.get('command', '').lower():
                            continue
                        
                        # Add source file info
                        entry['log_file'] = log_file.name
                        all_entries.append(entry)
                    except json.JSONDecodeError:
                        continue
        
        if not all_entries:
            return "📋 No matching log entries found"
        
        # Sort by timestamp
        all_entries.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        # Format output
        results = [f"📋 Command Execution Logs"]
        results.append(f"Directory: {LOG_DIR}")
        results.append("=" * 60)
        
        # Show summary
        unique_hosts = set(e.get('hostname', 'Unknown') for e in all_entries)
        results.append(f"Found {len(all_entries)} entries across {len(unique_hosts)} hosts")
        results.append("-" * 60)
        
        # Show last 50 entries
        for entry in all_entries[:50]:
            timestamp = entry.get('timestamp', 'Unknown')
            hostname = entry.get('hostname', 'Unknown')
            user = entry.get('user', 'Unknown')
            command = entry.get('command', 'Unknown')
            success = entry.get('success', False)
            log_file = entry.get('log_file', '')
            
            status = "✅" if success else "❌"
            results.append(f"\n{status} [{timestamp}]")
            results.append(f"File: {log_file} | Host: {hostname} | User: {user}")
            results.append(f"Command: {command}")
            
            if not success and entry.get('error'):
                results.append(f"Error: {entry['error'][:200]}")
        
        if len(all_entries) > 50:
            results.append(f"\n... and {len(all_entries) - 50} more entries")
        
        return "\n".join(results)
        
    except Exception as e:
        return f"❌ Error reading logs: {str(e)}"

@mcp.tool()
async def get_log_status() -> str:
    """Get current logging configuration and statistics."""
    logger.info("Getting log status")
    
    try:
        results = ["📊 Logging Status"]
        results.append("=" * 60)
        results.append(f"Log Directory: {LOG_DIR}")
        results.append(f"Directory Exists: {LOG_DIR.exists()}")
        
        if LOG_DIR.exists():
            # Get log files
            log_files = sorted(LOG_DIR.glob("*.json"))
            results.append(f"Total Log Files: {len(log_files)}")
            
            # Group by hostname
            hostnames = {}
            for f in log_files:
                # Parse hostname from filename (hostname-MMDDYYYY.json)
                parts = f.stem.rsplit('-', 1)
                if len(parts) == 2:
                    hostname = parts[0]
                    date = parts[1]
                    if hostname not in hostnames:
                        hostnames[hostname] = []
                    hostnames[hostname].append(date)
            
            results.append(f"\nHosts with Logs: {len(hostnames)}")
            results.append("-" * 40)
            
            for hostname, dates in sorted(hostnames.items()):
                results.append(f"  {hostname}: {len(dates)} log files")
                # Show recent dates
                recent = sorted(dates)[-3:]
                results.append(f"    Recent: {', '.join(recent)}")
            
            # Calculate total size
            total_size = sum(f.stat().st_size for f in log_files)
            size_mb = total_size / (1024 * 1024)
            results.append(f"\nTotal Size: {size_mb:.2f} MB")
            
            # Show recent activity
            if log_files:
                most_recent = max(log_files, key=lambda f: f.stat().st_mtime)
                mod_time = datetime.fromtimestamp(most_recent.stat().st_mtime)
                results.append(f"Most Recent Activity: {mod_time.strftime('%Y-%m-%d %H:%M:%S')}")
                results.append(f"Most Recent File: {most_recent.name}")
        else:
            results.append("\n⚠️ Log directory does not exist!")
            results.append("It will be created when the first command is logged.")
        
        return "\n".join(results)
        
    except Exception as e:
        return f"❌ Error getting log status: {str(e)}"

# === SERVER STARTUP ===
if __name__ == "__main__":
    logger.info("Starting Linux Administration MCP server...")
    logger.info(f"Log directory configured: {LOG_DIR}")
    logger.info("SSH secrets are now optional - credentials can be provided at runtime")
    
    # Check if logs directory exists (create on first write)
    if LOG_DIR.exists():
        logger.info(f"Log directory exists: {LOG_DIR}")
    else:
        logger.info(f"Log directory will be created on first command: {LOG_DIR}")
    
    # Check for SSH key (now optional)
    if SSH_KEY_PATH and os.path.exists(SSH_KEY_PATH):
        logger.info(f"Default SSH key found at {SSH_KEY_PATH}")
    else:
        logger.info("No default SSH key configured. Credentials must be provided at runtime.")
    
    try:
        # The FastMCP framework handles async internally, so we just call run()
        mcp.run(transport='stdio')
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)
