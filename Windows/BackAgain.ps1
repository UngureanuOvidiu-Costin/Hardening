# First thing to check: Is this shell elevated ?
$elevatedShell = ([Security.Principal.WindowsPrincipal] `
  [Security.Principal.WindowsIdentity]::GetCurrent() `
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
## This shell is not elevated, print message and exit
if($elevatedShell -eq $false) {
    Write-Host "Open Powershell with Administrative rights" -ForegroundColor Red
    exit 1
}


# Check free space
## Obtain all "drives" that are filesystems and also have more than 60GB free
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ge 60GB }  ## Didn't know, but comparators are smart
## Preferably, don't pick "C", because we are going to activate rotational archives and will eat the storage
$preferedDrive = $drives | Where-Object { $_.Name -ne "C" } | Select-Object -First 1
## If only "C" is available, let it be
if (-not $preferedDrive) {
    $preferedDrive = $drives | Where-Object { $_.Name -eq "C" }
}


# Backup IIS logs
## Test if IIS logs path exists
## DON'T check if it is Workstation/Server/Domain Controller, because IIS can be installed also on Workstations/DC
$iisLogsPath = Test-Path -Path "%SystemDrive%\inetpub\logs\LogFiles"
## If so, then archive
if ($iisLogsPath -eq $true) {
	Compress-Archive -Path $iisLogsPath -DestinationPath $preferedDrive\IIS_Logs.zip -CompresionLevel Fastest
}


# Enable Powershell Transcript
## Test if logs directory already exists
$pathAlreadyExists = Test-Path -Path "C:\PowerShell\Transcripts"
## Create the logs directory if it does not exist
if($pathAlreadyExists -eq $false) {
    New-Item -ItemType Directory -Path "C:\PowerShell\Transcripts"
}
## Registry: Enable Powershell Transcript
Set-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription -Name EnableTranscripting -Value 1 -Type DWord
## Registry: Configure Powershell Transcript to write logs to the previously created directory
Set-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription -Name OutputDirectory -Value "C:\PowerShell\Transcripts" -Type String
## Registry: Invocation Header is needed to log "Command start time"
Set-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription -Name EnableInvocationHeader -Value 1 -Type DWord


# Activate rotational archives for EVTX-files
## Increased size
## When Auto-Backup is combined with Retention: Rotational archives
wevutil el | ForEach-Object {
    try {
        wevutil sl "$_" /ms:1073741824 # Increased size
        wevutil sl "$_" /ab:true # Auto-Backup (Not enough alone)
        wevutil sl "$_" /rt:true # Retention
        Write-Host "Worked for: " + "$_"
    } catch {
        Write-Host "Didn't work for: " + "$_"
    }
}


# Enable Prefetch
## Workstation already have enabled this, but that's not the case for servers
## Check if the current host is a server (https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem?redirectedfrom=MSDN)
$osType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
### osType can be:
### 1: Work Station
### 2: Domain Controller
### 3: Server
if($osType -eq 2 -or $osType -eq 3) { # Maybe they didnt update documentation, so take into account only these two
    ### EnablePrefetcher can be:
    ### 0: Disabled
    ### 1: Only for applications
    ### 2: Only for boot
    ### 3: Apps + Boot
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 3 /f
    ## Only God knows where this is in Microsoft's documentation
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Prefetcher" /v MaxPrefetchFiles /t REG_DWORD /d 8192 /f
    Enable-MMAgent –OperationAPI
    net start sysmain
}
## Time to check if it works
$prefetchPath = "C:\Windows\Prefetch"
### Start Calculator app in order to generate a prefetch
$executableName = "calc.exe"
### Obtain a list of existing files in Prefetch (There shouldn't be many at the moment)
$before = Get-ChildItem $prefetchPath -Filter "$executableName*.pf" -ErrorAction SilentlyContinue
### Start Calculator process and use PassThru to return an object for the process
$proc = Start-Process "calc.exe" -PassThru
### If we start the process and kill it too fast, it won't generate a Prefetch file
Start-Sleep -Seconds 5
### Kill the process
Stop-Process -Id $proc.Id -Force
### Wait a little, maybe it won't get killed fast
Start-Sleep -Seconds 3
### Obtain a new list of existing files in Prefetch
$after = Get-ChildItem $prefetchPath -Filter "$executableName*pf" -ErrorAction SilentlyContinue
### Compare the number
if ($after.Count -le $before.Count) {
    Write-Host "Prefetch didn't work" -ForegroundColor Red
}


# Install Sysmon
## Download config file (RAW URL)
$xmlConfigFileURL = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$xmlLocalConfigPath = "C:\sysmon_config.xml"
Invoke-WebRequest -URI $xmlConfigFileURL -OutFile $xmlLocalConfigPath
if (!(Test-Path $xmlLocalConfigPath)) {
    Write-Host "Could not download config file" -ForegroundColor Red
    exit 1
}
## Download Sysmon
$sysmonArchiveURL = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonArchivePath = "C:\sysmon.zip"
$sysmonExtractPath = "C:\Sysmon"
Invoke-WebRequest -URI $sysmonArchiveURL -OutFile $sysmonArchivePath
if (!(Test-Path $sysmonArchivePath)) {
    Write-Host "Could not download Sysmon" -ForegroundColor Red
    exit 1
}
## Extract
Expand-Archive -Path $sysmonArchivePath -DestinationPath $sysmonExtractPath -Force
$sysmonExePath = "$sysmonExtractPath\Sysmon.exe"
if (!(Test-Path $sysmonExePath)) {
    Write-Host "Sysmon.exe not found after extraction" -ForegroundColor Red
    exit 1
}
## Install Sysmon
Start-Process -FilePath $sysmonExePath -ArgumentList "-accepteula -i $xmlLocalConfigPath" -Verb RunAs -Wait
## Check if the service is running
Start-Sleep -Seconds 5
$service = Get-Service -Name Sysmon -ErrorAction SilentlyContinue
if (!($service -and $service.Status -eq "Running")) {
    Write-Host "Sysmon Service is not running" -ForegroundColor Red
}


# Domain Controller database copy
## This means Domain Controller, check line 47 of the script
if ($osType -eq 3) {
    try{
        ntdsutil
        activate instance ntds
        ifm
        create full C:\CApC_ntdis_clone
        quit
        quit
    } catch {
        Write-Host "Could not create a copy of ntdis.dit" -ForegroundColor Red
    }
}

# Disable Administrative Share
## Why ? Why not ?
## Take into account that there might be a SCCM on the top right segment
## SCCM needs this Windows feature in order to push files (I don't know in what context)
## For $osType, check line 47 of the script
if ($osType -eq 1 -or $osType -eq 2) {  # Workstation or Windows Server (Not Domain Controller)
    ## On Domain Controllers we need share for Domain Policies
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name AutoShareWks -Value 0
    Restart-Service LanmanServer
}


# Domain Policy executables/scripts permissions on Domain Controller
## Extensions for files that can be added to be ran through policies
## Example, not limited to (Idk what an attacker could think about)
if($osType -eq 3) { ## Check line 47 of the script, 3 = Domain Controller
	$extensions = @(
	".exe",".com",".ps1",".bat",".cmd",
	".vbs",".js",".jse",".vbe",".wsf",".wsh",
	".msi",".msp",".lnk",".dll",".hta",".scr",".cpl"
	)

	## Extract files with desired extensions
	$domainControllerFQDN = (Get-ADDomainController -Filter *).HostName
	$runnableFiles = Get-ChildItem -Path "\\$domainControllerFQDN\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse |
	Where-Object {
		$_.Extension -in $extensions
	}

	## Default, a domain policy has these groups/users:
	### <Domain>\Domain Admins: FullControl
	### <Domain>\Enterprise Admins: FullControl
	### NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS: ReadAndExecute, Synchronize
	### NT AUTHORITY\Authenticated Users: ReadAndExecute, Synchronize
	### NT AUTHORITY\SYSTEM: FullControl
	### BUILTIN\Administrators: FullControl
	### We need to make sure that nobody has write access (averge user)
	### We define a HashMap(Java) or Dictionary(Python)
	$defaultACLUsersGroups = @{
	"builtin\administrators" = "FullControl"
	"nt authority\system" = "FullControl"
	"nt authority\authenticated users" = @("ReadAndExecute", "Synchronize")
	"nt authority\enterprise domain controllers" = @("ReadAndExecute", "Synchronize")
	"$((Get-ADDomain).NetBIOSName.ToUpper())\enterprise admins" = "FullControl"
	"$((Get-ADDomain).NetBIOSName.ToUpper())\domain admins" = "FullControl"
	}


	## Iterate through the files
	foreach ($file in $runnableFiles) {

		### Obtain the access control list object for each file
		$accessList = Get-Acl $file.FullName ## FullName = full path of the file
		### Obtain a list only of access objects
		$aclList = $accessList.Access
		
		### Iterate through each "System.Security.AccessControl.AuthorizationRuleCollection" which is a list itself
		foreach ($aclObject in $aclList) {
		
			$userOrGroup = $aclObject.IdentityReference.Value.ToLower()
			$permissions = $aclObject.FileSystemRights ### String
			### Split the permissions into an array
			$actualPermissions = $permissions -split ",\s*"
			### Check if the user or the group is NOT in the baseline
			if(-not $defaultACLUsersGroups.ContainsKey($userOrGroup)) {
				Write-Host "Extra user or group for $($file.FullName): $userOrGroup ($permissions)" -ForegroundColor Red
				continue
			}
			### Obtain the permissions as a single value or array
			$baseline = $defaultACLUsersGroups[$userOrGroup]
			### Convert to an array with a single value (it is easier to search)
			if($baseline -isnot [array]) {
				$baseline = @($baseline)
			}

			### Iterathe through the permissions and check if it was inside the baseline
			foreach ($perm in $actualPermissions) {
				if ($perm -notin $baseline) {
					Write-Host "Extra permission on $($file.FullName)" -ForegroundColor Magenta
					Write-Host "      $userOrGroup -> $perm (All permissions: $permissions)" -ForegroundColor Magenta
				}
			}
		}
	}
}


# Get Users with password not required
Get-ADUser -Filter { PasswordNotRequired -eq $true } | foreach {
    Write-Host "User $_ has no password set" -ForegroundColor Red
}




