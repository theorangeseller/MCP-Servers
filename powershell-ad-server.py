import os
import subprocess
import platform
import json
import re
from datetime import datetime
from typing import Dict, Any, Optional, List
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("PowerShell-AD-Server")

# Audit logging function (following existing pattern)
def write_audit_log(command: str, user: str, success: bool, result: str = "", error: str = ""):
    """
    Write audit log for PowerShell command execution.
    
    Args:
        command: The PowerShell command executed
        user: User who executed the command
        success: Whether the command was successful
        result: Command result (truncated for logging)
        error: Error message if any
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Set the log folder path
    log_folder = "/Users/stewart/VSCode/MCP-Servers/logs"
    os.makedirs(log_folder, exist_ok=True)
    
    # Create the audit log file
    log_file = os.path.join(log_folder, "powershell_audit.log")
    
    # Truncate result for logging (max 200 chars)
    truncated_result = result[:200] + "..." if len(result) > 200 else result
    
    status = "SUCCESS" if success else "FAILED"
    log_entry = f"{timestamp} - {status} - User: {user} - Command: {command}"
    if error:
        log_entry += f" - Error: {error}"
    if truncated_result:
        log_entry += f" - Result: {truncated_result}"
    log_entry += "\n"
    
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(log_entry)
    
    print(f"Audit log written to {log_file}")

# Whitelist of allowed PowerShell AD commands (Get commands only for security)
ALLOWED_AD_COMMANDS = {
    "Get-ADUser": {
        "description": "Gets one or more Active Directory users",
        "common_params": ["-Identity", "-Filter", "-Properties", "-SearchBase", "-Server"]
    },
    "Get-ADGroup": {
        "description": "Gets one or more Active Directory groups",
        "common_params": ["-Identity", "-Filter", "-Properties", "-SearchBase", "-Server"]
    },
    "Get-ADGroupMember": {
        "description": "Gets the members of an Active Directory group",
        "common_params": ["-Identity", "-Recursive", "-Server"]
    },
    "Get-ADComputer": {
        "description": "Gets one or more Active Directory computers",
        "common_params": ["-Identity", "-Filter", "-Properties", "-SearchBase", "-Server"]
    },
    "Get-ADDomain": {
        "description": "Gets an Active Directory domain",
        "common_params": ["-Identity", "-Server"]
    },
    "Get-ADDomainController": {
        "description": "Gets one or more Active Directory domain controllers",
        "common_params": ["-Identity", "-Filter", "-Server"]
    },
    "Get-ADObject": {
        "description": "Gets one or more Active Directory objects",
        "common_params": ["-Identity", "-Filter", "-Properties", "-SearchBase", "-Server"]
    },
    "Get-ADOrganizationalUnit": {
        "description": "Gets one or more Active Directory organizational units",
        "common_params": ["-Identity", "-Filter", "-Properties", "-SearchBase", "-Server"]
    },
    "Get-ADForest": {
        "description": "Gets an Active Directory forest",
        "common_params": ["-Identity", "-Server"]
    },
    "Get-ADDefaultDomainPasswordPolicy": {
        "description": "Gets the default password policy for an Active Directory domain",
        "common_params": ["-Identity", "-Server"]
    },
    "Get-ADFineGrainedPasswordPolicy": {
        "description": "Gets one or more Active Directory fine-grained password policies",
        "common_params": ["-Identity", "-Filter", "-Server"]
    },
    "Get-ADAccountAuthorizationGroup": {
        "description": "Gets the accounts token group information",
        "common_params": ["-Identity", "-Server"]
    },
    "Get-ADAuthenticationPolicy": {
        "description": "Gets one or more Active Directory Domain Services authentication policies",
        "common_params": ["-Identity", "-Filter", "-Server"]
    },
    "Get-ADReplicationSite": {
        "description": "Gets a specific Active Directory replication site or a set of replication site objects",
        "common_params": ["-Identity", "-Filter", "-Server"]
    },
    "Get-ADReplicationConnection": {
        "description": "Returns a specific Active Directory replication connection or a set of AD replication connection objects",
        "common_params": ["-Identity", "-Filter", "-Server"]
    },
    "Get-ADReplicationSubnet": {
        "description": "Gets one or more Active Directory replication subnets",
        "common_params": ["-Identity", "-Filter", "-Server"]
    },
    "Get-ADServiceAccount": {
        "description": "Gets one or more Active Directory managed service accounts or group managed service accounts",
        "common_params": ["-Identity", "-Filter", "-Properties", "-Server"]
    },
    "Get-ADTrust": {
        "description": "Returns a specific Active Directory trust or a set of AD trust objects",
        "common_params": ["-Identity", "-Filter", "-Server"]
    }
}

def validate_powershell_command(command: str) -> bool:
    """
    Validate PowerShell command against whitelist and dangerous patterns.
    
    Args:
        command: PowerShell command to validate
        
    Returns:
        bool: True if command is safe, False otherwise
    """
    # Remove extra whitespace and normalize
    command = command.strip()
    
    # Check if command starts with allowed AD command
    command_name = command.split()[0] if command.split() else ""
    if command_name not in ALLOWED_AD_COMMANDS:
        return False
    
    # Check for dangerous patterns
    dangerous_patterns = [
        r';', r'&', r'\$\(', r'`', r'Invoke-Expression', r'\biex\b',
        r'Invoke-Command', r'Start-Process', r'New-Object', r'Invoke-WebRequest',
        r'curl', r'wget', r'Remove-', r'Delete-', r'Set-', r'New-', r'Add-',
        r'Clear-', r'Disable-', r'Enable-', r'Install-', r'Uninstall-'
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, command, re.IGNORECASE):
            return False
    
    return True

def execute_powershell_command(command: str, timeout: int = 30) -> Dict[str, Any]:
    """
    Execute PowerShell command safely with validation and logging.
    
    Args:
        command: PowerShell command to execute
        timeout: Timeout in seconds
        
    Returns:
        Dict with output, error, return_code, and success status
    """
    try:
        # Validate command
        if not validate_powershell_command(command):
            raise ValueError(f"Command not allowed or contains dangerous patterns: {command}")
        
        # Determine PowerShell executable
        if platform.system() == "Windows":
            ps_cmd = ["powershell.exe"]
        else:
            # For macOS/Linux with PowerShell Core
            ps_cmd = ["pwsh"]
        
        # Build safe command with restricted execution policy
        full_command = ps_cmd + [
            "-NoProfile",
            "-NonInteractive", 
            "-NoLogo",
            "-ExecutionPolicy", "Restricted",
            "-Command", command
        ]
        
        # Execute command
        result = subprocess.run(
            full_command,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding='utf-8'
        )
        
        return {
            "output": result.stdout.strip(),
            "error": result.stderr.strip(),
            "return_code": result.returncode,
            "success": result.returncode == 0,
            "command_executed": command
        }
        
    except subprocess.TimeoutExpired:
        return {
            "output": "",
            "error": f"Command timed out after {timeout} seconds",
            "return_code": 1,
            "success": False,
            "command_executed": command
        }
    except Exception as e:
        return {
            "output": "",
            "error": str(e),
            "return_code": 1,
            "success": False,
            "command_executed": command
        }

@mcp.tool()
def get_ad_user(identity: str = "", filter_expression: str = "", properties: str = "Name,SamAccountName,EmailAddress,Enabled", user: str = "system") -> Dict[str, Any]:
    """
    Get Active Directory user information using Get-ADUser command.
    
    Args:
        identity: Specific user identity (SamAccountName, DistinguishedName, GUID, or SID)
        filter_expression: PowerShell filter expression (e.g., "Name -like 'John*'")
        properties: Comma-separated list of properties to retrieve
        user: Username for audit logging
    
    Returns:
        Dictionary containing user information or error details
    """
    try:
        # Build PowerShell command
        if identity:
            command = f"Get-ADUser -Identity '{identity}'"
        elif filter_expression:
            command = f"Get-ADUser -Filter '{filter_expression}'"
        else:
            command = "Get-ADUser -Filter *"
        
        # Add properties if specified
        if properties:
            command += f" -Properties {properties}"
        
        # Add output formatting for JSON
        command += " | ConvertTo-Json -Depth 3"
        
        # Execute command
        result = execute_powershell_command(command)
        
        # Log audit information
        write_audit_log(
            command=command,
            user=user,
            success=result["success"],
            result=result["output"],
            error=result["error"]
        )
        
        if result["success"]:
            try:
                # Parse JSON output
                user_data = json.loads(result["output"]) if result["output"] else []
                return {
                    "success": True,
                    "data": user_data,
                    "command": command,
                    "count": len(user_data) if isinstance(user_data, list) else 1
                }
            except json.JSONDecodeError:
                return {
                    "success": True,
                    "data": result["output"],
                    "command": command,
                    "note": "Raw output (JSON parsing failed)"
                }
        else:
            return {
                "success": False,
                "error": result["error"],
                "command": command
            }
            
    except Exception as e:
        error_msg = f"Error executing Get-ADUser: {str(e)}"
        write_audit_log(
            command=f"Get-ADUser (failed validation)",
            user=user,
            success=False,
            error=error_msg
        )
        return {
            "success": False,
            "error": error_msg
        }

@mcp.tool()
def get_ad_group(identity: str = "", filter_expression: str = "", properties: str = "Name,GroupCategory,GroupScope,Members", user: str = "system") -> Dict[str, Any]:
    """
    Get Active Directory group information using Get-ADGroup command.
    
    Args:
        identity: Specific group identity (Name, DistinguishedName, GUID, or SID)
        filter_expression: PowerShell filter expression (e.g., "Name -like 'Admin*'")
        properties: Comma-separated list of properties to retrieve
        user: Username for audit logging
    
    Returns:
        Dictionary containing group information or error details
    """
    try:
        # Build PowerShell command
        if identity:
            command = f"Get-ADGroup -Identity '{identity}'"
        elif filter_expression:
            command = f"Get-ADGroup -Filter '{filter_expression}'"
        else:
            command = "Get-ADGroup -Filter *"
        
        # Add properties if specified
        if properties:
            command += f" -Properties {properties}"
        
        # Add output formatting for JSON
        command += " | ConvertTo-Json -Depth 3"
        
        # Execute command
        result = execute_powershell_command(command)
        
        # Log audit information
        write_audit_log(
            command=command,
            user=user,
            success=result["success"],
            result=result["output"],
            error=result["error"]
        )
        
        if result["success"]:
            try:
                # Parse JSON output
                group_data = json.loads(result["output"]) if result["output"] else []
                return {
                    "success": True,
                    "data": group_data,
                    "command": command,
                    "count": len(group_data) if isinstance(group_data, list) else 1
                }
            except json.JSONDecodeError:
                return {
                    "success": True,
                    "data": result["output"],
                    "command": command,
                    "note": "Raw output (JSON parsing failed)"
                }
        else:
            return {
                "success": False,
                "error": result["error"],
                "command": command
            }
            
    except Exception as e:
        error_msg = f"Error executing Get-ADGroup: {str(e)}"
        write_audit_log(
            command=f"Get-ADGroup (failed validation)",
            user=user,
            success=False,
            error=error_msg
        )
        return {
            "success": False,
            "error": error_msg
        }

@mcp.tool()
def get_ad_group_member(identity: str, recursive: bool = False, user: str = "system") -> Dict[str, Any]:
    """
    Get Active Directory group members using Get-ADGroupMember command.
    
    Args:
        identity: Group identity (Name, DistinguishedName, GUID, or SID)
        recursive: Whether to get members recursively (nested groups)
        user: Username for audit logging
    
    Returns:
        Dictionary containing group member information or error details
    """
    try:
        # Build PowerShell command
        command = f"Get-ADGroupMember -Identity '{identity}'"
        
        if recursive:
            command += " -Recursive"
        
        # Add output formatting for JSON
        command += " | ConvertTo-Json -Depth 3"
        
        # Execute command
        result = execute_powershell_command(command)
        
        # Log audit information
        write_audit_log(
            command=command,
            user=user,
            success=result["success"],
            result=result["output"],
            error=result["error"]
        )
        
        if result["success"]:
            try:
                # Parse JSON output
                member_data = json.loads(result["output"]) if result["output"] else []
                return {
                    "success": True,
                    "data": member_data,
                    "command": command,
                    "count": len(member_data) if isinstance(member_data, list) else 1,
                    "recursive": recursive
                }
            except json.JSONDecodeError:
                return {
                    "success": True,
                    "data": result["output"],
                    "command": command,
                    "note": "Raw output (JSON parsing failed)"
                }
        else:
            return {
                "success": False,
                "error": result["error"],
                "command": command
            }
            
    except Exception as e:
        error_msg = f"Error executing Get-ADGroupMember: {str(e)}"
        write_audit_log(
            command=f"Get-ADGroupMember (failed validation)",
            user=user,
            success=False,
            error=error_msg
        )
        return {
            "success": False,
            "error": error_msg
        }

@mcp.tool()
def get_ad_computer(identity: str = "", filter_expression: str = "", properties: str = "Name,OperatingSystem,LastLogonDate,Enabled", user: str = "system") -> Dict[str, Any]:
    """
    Get Active Directory computer information using Get-ADComputer command.
    
    Args:
        identity: Specific computer identity (Name, DistinguishedName, GUID, or SID)
        filter_expression: PowerShell filter expression (e.g., "Name -like 'Server*'")
        properties: Comma-separated list of properties to retrieve
        user: Username for audit logging
    
    Returns:
        Dictionary containing computer information or error details
    """
    try:
        # Build PowerShell command
        if identity:
            command = f"Get-ADComputer -Identity '{identity}'"
        elif filter_expression:
            command = f"Get-ADComputer -Filter '{filter_expression}'"
        else:
            command = "Get-ADComputer -Filter *"
        
        # Add properties if specified
        if properties:
            command += f" -Properties {properties}"
        
        # Add output formatting for JSON
        command += " | ConvertTo-Json -Depth 3"
        
        # Execute command
        result = execute_powershell_command(command)
        
        # Log audit information
        write_audit_log(
            command=command,
            user=user,
            success=result["success"],
            result=result["output"],
            error=result["error"]
        )
        
        if result["success"]:
            try:
                # Parse JSON output
                computer_data = json.loads(result["output"]) if result["output"] else []
                return {
                    "success": True,
                    "data": computer_data,
                    "command": command,
                    "count": len(computer_data) if isinstance(computer_data, list) else 1
                }
            except json.JSONDecodeError:
                return {
                    "success": True,
                    "data": result["output"],
                    "command": command,
                    "note": "Raw output (JSON parsing failed)"
                }
        else:
            return {
                "success": False,
                "error": result["error"],
                "command": command
            }
            
    except Exception as e:
        error_msg = f"Error executing Get-ADComputer: {str(e)}"
        write_audit_log(
            command=f"Get-ADComputer (failed validation)",
            user=user,
            success=False,
            error=error_msg
        )
        return {
            "success": False,
            "error": error_msg
        }

@mcp.tool()
def get_ad_domain(identity: str = "", user: str = "system") -> Dict[str, Any]:
    """
    Get Active Directory domain information using Get-ADDomain command.
    
    Args:
        identity: Domain identity (NetBIOS name, FQDN, or distinguished name)
        user: Username for audit logging
    
    Returns:
        Dictionary containing domain information or error details
    """
    try:
        # Build PowerShell command
        if identity:
            command = f"Get-ADDomain -Identity '{identity}'"
        else:
            command = "Get-ADDomain"
        
        # Add output formatting for JSON
        command += " | ConvertTo-Json -Depth 3"
        
        # Execute command
        result = execute_powershell_command(command)
        
        # Log audit information
        write_audit_log(
            command=command,
            user=user,
            success=result["success"],
            result=result["output"],
            error=result["error"]
        )
        
        if result["success"]:
            try:
                # Parse JSON output
                domain_data = json.loads(result["output"]) if result["output"] else {}
                return {
                    "success": True,
                    "data": domain_data,
                    "command": command
                }
            except json.JSONDecodeError:
                return {
                    "success": True,
                    "data": result["output"],
                    "command": command,
                    "note": "Raw output (JSON parsing failed)"
                }
        else:
            return {
                "success": False,
                "error": result["error"],
                "command": command
            }
            
    except Exception as e:
        error_msg = f"Error executing Get-ADDomain: {str(e)}"
        write_audit_log(
            command=f"Get-ADDomain (failed validation)",
            user=user,
            success=False,
            error=error_msg
        )
        return {
            "success": False,
            "error": error_msg
        }

@mcp.tool()
def get_ad_domain_controller(identity: str = "", filter_expression: str = "", user: str = "system") -> Dict[str, Any]:
    """
    Get Active Directory domain controller information using Get-ADDomainController command.
    
    Args:
        identity: Specific domain controller identity
        filter_expression: PowerShell filter expression
        user: Username for audit logging
    
    Returns:
        Dictionary containing domain controller information or error details
    """
    try:
        # Build PowerShell command
        if identity:
            command = f"Get-ADDomainController -Identity '{identity}'"
        elif filter_expression:
            command = f"Get-ADDomainController -Filter '{filter_expression}'"
        else:
            command = "Get-ADDomainController -Filter *"
        
        # Add output formatting for JSON
        command += " | ConvertTo-Json -Depth 3"
        
        # Execute command
        result = execute_powershell_command(command)
        
        # Log audit information
        write_audit_log(
            command=command,
            user=user,
            success=result["success"],
            result=result["output"],
            error=result["error"]
        )
        
        if result["success"]:
            try:
                # Parse JSON output
                dc_data = json.loads(result["output"]) if result["output"] else []
                return {
                    "success": True,
                    "data": dc_data,
                    "command": command,
                    "count": len(dc_data) if isinstance(dc_data, list) else 1
                }
            except json.JSONDecodeError:
                return {
                    "success": True,
                    "data": result["output"],
                    "command": command,
                    "note": "Raw output (JSON parsing failed)"
                }
        else:
            return {
                "success": False,
                "error": result["error"],
                "command": command
            }
            
    except Exception as e:
        error_msg = f"Error executing Get-ADDomainController: {str(e)}"
        write_audit_log(
            command=f"Get-ADDomainController (failed validation)",
            user=user,
            success=False,
            error=error_msg
        )
        return {
            "success": False,
            "error": error_msg
        }

@mcp.tool()
def get_ad_user_lockout_status(identity: str, user: str = "system") -> Dict[str, Any]:
    """
    Check if an Active Directory user account is locked out.
    
    Args:
        identity: User identity (SamAccountName, UPN, DistinguishedName, GUID, or SID)
        user: Username for audit logging
    
    Returns:
        Dictionary containing lockout status or error details
    """
    try:
        # Build PowerShell command
        command = (
            f"Get-ADUser -Identity '{identity}' "
            "-Properties LockedOut,AccountLockoutTime "
            "| Select-Object Name,SamAccountName,UserPrincipalName,LockedOut,AccountLockoutTime "
            "| ConvertTo-Json -Depth 3"
        )
        
        # Execute command
        result = execute_powershell_command(command)
        
        # Log audit information
        write_audit_log(
            command=command,
            user=user,
            success=result["success"],
            result=result["output"],
            error=result["error"]
        )
        
        if result["success"]:
            try:
                # Parse JSON output
                lockout_data = json.loads(result["output"]) if result["output"] else {}
                return {
                    "success": True,
                    "identity": identity,
                    "locked_out": bool(lockout_data.get("LockedOut", False)) if isinstance(lockout_data, dict) else False,
                    "account_lockout_time": lockout_data.get("AccountLockoutTime") if isinstance(lockout_data, dict) else None,
                    "data": lockout_data,
                    "command": command
                }
            except json.JSONDecodeError:
                return {
                    "success": True,
                    "identity": identity,
                    "data": result["output"],
                    "command": command,
                    "note": "Raw output (JSON parsing failed)"
                }
        else:
            return {
                "success": False,
                "identity": identity,
                "error": result["error"],
                "command": command
            }
            
    except Exception as e:
        error_msg = f"Error executing lockout status check: {str(e)}"
        write_audit_log(
            command="Get-ADUser lockout status (failed validation)",
            user=user,
            success=False,
            error=error_msg
        )
        return {
            "success": False,
            "identity": identity,
            "error": error_msg
        }

@mcp.tool()
def execute_custom_ad_get_command(command: str, user: str = "system") -> Dict[str, Any]:
    """
    Execute a custom Active Directory 'Get-' command with full validation.
    
    Args:
        command: Full PowerShell Get-AD* command to execute
        user: Username for audit logging
    
    Returns:
        Dictionary containing command output or error details
    """
    try:
        # Add JSON conversion if not present
        if "ConvertTo-Json" not in command:
            command += " | ConvertTo-Json -Depth 3"
        
        # Execute command
        result = execute_powershell_command(command)
        
        # Log audit information
        write_audit_log(
            command=command,
            user=user,
            success=result["success"],
            result=result["output"],
            error=result["error"]
        )
        
        if result["success"]:
            try:
                # Parse JSON output
                data = json.loads(result["output"]) if result["output"] else {}
                return {
                    "success": True,
                    "data": data,
                    "command": command,
                    "raw_output": result["output"]
                }
            except json.JSONDecodeError:
                return {
                    "success": True,
                    "data": result["output"],
                    "command": command,
                    "note": "Raw output (JSON parsing failed)"
                }
        else:
            return {
                "success": False,
                "error": result["error"],
                "command": command
            }
            
    except Exception as e:
        error_msg = f"Error executing custom AD command: {str(e)}"
        write_audit_log(
            command=f"execute_custom_ad_get_command (failed validation)",
            user=user,
            success=False,
            error=error_msg
        )
        return {
            "success": False,
            "error": error_msg
        }

@mcp.tool()
def list_available_ad_commands(user: str = "system") -> Dict[str, Any]:
    """
    List all available Active Directory commands in this MCP server.
    
    Args:
        user: Username for audit logging
    
    Returns:
        Dictionary containing available commands and their descriptions
    """
    try:
        # Log audit information
        write_audit_log(
            command="list_available_ad_commands",
            user=user,
            success=True,
            result="Listed available AD commands"
        )
        
        return {
            "success": True,
            "available_commands": ALLOWED_AD_COMMANDS,
            "security_note": "Only 'Get-' commands are allowed for security. All commands are logged and validated.",
            "total_commands": len(ALLOWED_AD_COMMANDS)
        }
        
    except Exception as e:
        error_msg = f"Error listing available commands: {str(e)}"
        write_audit_log(
            command="list_available_ad_commands",
            user=user,
            success=False,
            error=error_msg
        )
        return {
            "success": False,
            "error": error_msg
        }

if __name__ == "__main__":
    # Initialize and run the server
    print("Starting PowerShell Active Directory MCP Server...")
    print("Available commands:")
    for cmd, info in ALLOWED_AD_COMMANDS.items():
        print(f"  - {cmd}: {info['description']}")
    print("\nSecurity features:")
    print("  - Command validation and whitelisting")
    print("  - Audit logging to logs/powershell_audit.log") 
    print("  - Input sanitization")
    print("  - Timeout protection")
    print("  - Only 'Get-' commands allowed")
    
    mcp.run(transport='stdio') 