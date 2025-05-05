```Powershell
# LS-WindowsAudit.ps1
# Author: HashMap (UngureanuOvidiu-Costin on Github)
# Usage: Run as Admin


# Simple function to prompt text as red in case of something bad
function Write-RedAlert {
    param ($message)
    Write-Host "[!] $message" -ForegroundColor Red
}


# This serves no purpose, just to know that the script started
Write-Host "=== Windows Audit Script ===" -ForegroundColor Cyan


# Waitfor backdoor (scanning running processes)
# Look for potential "waitfor" backdoor trigger in scheduled tasks
# Look for potential powershell.exe/cmd.exe
Get-ScheduledTask | ForEach-Object {
    $task = $_
    $actions = $task.Actions | ForEach-Object {
        $_.Execute + " " + $_.Arguments
    }
    foreach ($action in $actions) {
        if ($action -match "waitfor") {
            Write-RedAlert "WaitFor backdoor via Scheduled Task: $($task.TaskName)"
        }else {
            if ($action -match "cmd.exe|powershell.exe") {
                Write-RedAlert "Suspicious shell in Scheduled Task: $($task.TaskName) -> $action"
            }
        }
    }
}


# Unauthenticated SSH account (check for SSH + blank passwords)
# These accounts could be used to run services
Get-LocalUser | Where-Object { $_.Enabled -eq $true } | ForEach-Object {
    try {
        $pass = ([ADSI]"WinNT://$env:COMPUTERNAME/$($_.Name),user").PasswordRequired
        if (-not $pass) {
            Write-RedAlert "Account '$($_.Name)' has no password set."
        }
    } catch {}
}


# Modifiable Logon Script
# If an attacker modifies \\domain\NETLOGON\Logon.cmd, they can execute arbitrary commands on 
# every workstation and server where a domain user logs in
$domainRoot = (Get-ADDomain).DNSRoot
# Build UNC path to Logon.cmd inside NETLOGON share
$logonScriptUNC = "\\$domainRoot\NETLOGON\Logon.cmd"
if (Test-Path $logonScriptUNC) {
    $acl = Get-Acl $logonScriptUNC
    $acl.Access | Where-Object {
        $_.FileSystemRights -match "Write|FullControl" -and $_.IdentityReference -match "Users|Guest|Guests|Everyone|Domain Users"
    } | ForEach-Object {
        Write-RedAlert "NETLOGON\Logon.cmd is modifiable by Users: $($_.IdentityReference)"
    }
} else {
    Write-Host "Logon.cmd not found at $logonScriptUNC"
}


# Check AdminSDHolder Permissions
# AdminSDHolder is a critical object in Active Directory that controls security descriptor inheritance for high-privileged accounts and groups — like:
# - Domain Admins
# - Enterprise Admins
# - Schema Admins
# - Administrators
# - Backup Operators, etc.
# Every hour, the SDProp (Security Descriptor Propagator) process runs on the PDC Emulator and overwrites 
# the ACLs (permissions) of all protected accounts with the permissions from the AdminSDHolder object.
try {
    $adminSDHolder = Get-ADObject -Filter 'Name -eq "AdminSDHolder"'
    $acl = Get-Acl "AD:$($adminSDHolder.DistinguishedName)"
    $acl.Access | Where-Object {
        $_.IdentityReference -notmatch "Domain Admins|Enterprise Admins|Administrators|NT AUTHORITY\\SYSTEM|NT AUTHORITY\\SELF|BUILTIN\Terminal Server License Servers" -and
        $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteProperty"
    } | ForEach-Object {
        Write-RedAlert "Non-privileged user '$($_.IdentityReference)' has dangerous permissions on AdminSDHolder."
    }
} catch {}


# IFEO persistence
# IFEO is a feature in Windows designed for developers. It allows them to set specific execution options for an image file (executable) without modifying the actual binary code. 
# https://securityblueteam.medium.com/utilizing-image-file-execution-options-ifeo-for-stealthy-persistence-331bc972554e
$ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
try {
    $subkeys = Get-ChildItem -Path $ifeoPath -ErrorAction Stop
    foreach ($subkey in $subkeys) {
        $debugger = Get-ItemProperty -Path $subkey.PSPath -Name "Debugger" -ErrorAction SilentlyContinue
        if ($debugger -and $debugger.Debugger) {
            Write-RedAlert "IFEO persistence: $($subkey.PSChildName) => Debugger = $($debugger.Debugger)"
        }
    }
} catch {}


# Kerberos pre-auth disabled
# This is used for AS-REP Roasting, where attackers can try to crack the hashed tickets offline.
try {
    Get-ADUser -Filter * -Properties DoesNotRequirePreAuth | Where-Object {
        $_.DoesNotRequirePreAuth -eq $true
    } | ForEach-Object {
        Write-RedAlert "User $($_.SamAccountName) has DONT_REQ_PREAUTH set (AS-REP Roasting possible)."
    }
} catch {}


# DCSync detection (Check permissions on domain objects)
# DCSync is a technique that allows an attacker to simulate the behavior of a Domain Controller 
# (DC) and request replication of credentials
# IdentityReference is an Enum 
try {
    $dcSyncRights = (Get-ADDomain).DistinguishedName
    $dacl = Get-Acl "AD:\$dcSyncRights"

    $suspicious = $dacl.Access | Where-Object {
        $_.ActiveDirectoryRights -match "CreateChild|DeleteChild|WriteProperty|DeleteTree|Delete|GenericWrite|WriteDacl|WriteOwner|AccessSystemSecurity" -and
        $_.IdentityReference -notmatch "Domain Admins|Enterprise Admins|Administrators|NT AUTHORITY\\SELF"
    } | Select-Object -ExpandProperty IdentityReference -Unique

    foreach ($entry in $suspicious) {
        Write-RedAlert "Possible DCSync access: $entry"
    }
} catch {
    Write-Warning "Error analyzing DCSync rights: $_"
}


# Winlogon persistence
# Winlogon persistence is a technique used by attackers or malware to maintain access 
# by injecting malicious commands or binaries that are executed when a user logs in to a Windows system.
try {
    $shell = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -ErrorAction Stop
    if ($shell -and $shell -notmatch "explorer.exe") {
        Write-RedAlert "Winlogon persistence: Shell = $shell"
    }
} catch {}
try {
    $userinit = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit" -ErrorAction Stop
    if ($userinit -and $userinit -notmatch "userinit.exe") {
        Write-RedAlert "Winlogon persistence: Userinit = $userinit"
    }
} catch {}
```
