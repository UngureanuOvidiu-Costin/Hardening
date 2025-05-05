## Exchange Server

### ProxyLogon
https://github.com/RickGeex/ProxyLogon

### ProxyShell
[https://github.com/RickGeex/ProxyLogon](https://github.com/kh4sh3i/ProxyShell)

### CVE-2020-0688
https://github.com/MrTiz/CVE-2020-0688
https://nvd.nist.gov/vuln/detail/cve-2020-0688

### CVE-2021-42321
https://github.com/DarkSprings/CVE-2021-42321

### CVE-2021-26855
1. Documentation: https://microsoft.github.io/CSS-Exchange/Security/Test-ProxyLogon/
2. The script from the documentation
```Powershell
<#
    MIT License

    Copyright (c) Microsoft Corporation.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE
#>

# Version 24.10.24.2038

# Checks for signs of exploit from CVE-2021-26855, 26858, 26857, and 27065.
#
# Examples
#
# Check the local Exchange server only and save the report:
# .\Test-ProxyLogon.ps1 -OutPath $home\desktop\logs
#
# Check the local Exchange server, copy the files and folders to the OutPath\<ComputerName>\ path
# .\Test-ProxyLogon.ps1 -OutPath $home\desktop\logs -CollectFiles
#
# Check all Exchange servers and save the reports:
# Get-ExchangeServer | .\Test-ProxyLogon.ps1 -OutPath $home\desktop\logs
#
# Check all Exchange servers, but only display the results, don't save them:
# Get-ExchangeServer | .\Test-ProxyLogon.ps1 -DisplayOnly
#
#Requires -Version 3

[CmdletBinding(DefaultParameterSetName = "AsScript")]
param (
    [Parameter(ParameterSetName = "AsScript", ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('Fqdn')]
    [string[]]
    $ComputerName,

    [Parameter(ParameterSetName = "AsScript")]
    [string]
    $OutPath = "$PSScriptRoot\Test-ProxyLogonLogs",

    [Parameter(ParameterSetName = "AsScript")]
    [switch]
    $DisplayOnly,

    [Parameter(ParameterSetName = "AsScript")]
    [switch]
    $CollectFiles,

    [Parameter(ParameterSetName = 'AsModule')]
    [switch]
    $Export,

    [Parameter(ParameterSetName = "AsScript")]
    [System.Management.Automation.PSCredential]
    $Credential
)
begin {
    #region Functions
    function Test-ExchangeProxyLogon {
        <#
    .SYNOPSIS
        Checks targeted exchange servers for signs of ProxyLogon vulnerability compromise.

    .DESCRIPTION
        Checks targeted exchange servers for signs of ProxyLogon vulnerability compromise.

        Will do so in parallel if more than one server is specified, so long as names aren't provided by pipeline.
        The vulnerabilities are described in CVE-2021-26855, 26858, 26857, and 27065

    .PARAMETER ComputerName
        The list of server names to scan for signs of compromise.
        Do not provide these by pipeline if you want parallel processing.

    .PARAMETER Credential
        Credentials to use for remote connections.

    .EXAMPLE
        PS C:\> Test-ExchangeProxyLogon

        Scans the current computer for signs of ProxyLogon vulnerability compromise.

    .EXAMPLE
        PS C:\> Test-ExchangeProxyLogon -ComputerName (Get-ExchangeServer).Fqdn

        Scans all exchange servers in the organization for ProxyLogon vulnerability compromises
#>
        [CmdletBinding()]
        param (
            [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
            [string[]]
            $ComputerName,

            [System.Management.Automation.PSCredential]
            $Credential
        )
        begin {
            #region Remoting Scriptblock
            $scriptBlock = {
                #region Functions
                function Get-ExchangeInstallPath {
                    return (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
                }

                function Get-Cve26855 {
                    [CmdletBinding()]
                    param ()

                    $exchangePath = Get-ExchangeInstallPath
                    if ($null -eq $exchangePath) {
                        Write-Host "  Exchange 2013 or later not found. Skipping CVE-2021-26855 test."
                        return
                    }

                    $HttpProxyPath = Join-Path -Path $exchangePath -ChildPath "Logging\HttpProxy"
                    $Activity = "Checking for CVE-2021-26855 in the HttpProxy logs"

                    $outProps = @(
                        "DateTime", "RequestId", "ClientIPAddress", "UrlHost",
                        "UrlStem", "RoutingHint", "UserAgent", "AnchorMailbox",
                        "HttpStatus"
                    )

                    $files = [System.Array](Get-ChildItem -Recurse -Path $HttpProxyPath -Filter '*.log').FullName

                    $allResults = @{
                        Hits     = [System.Collections.ArrayList]@()
                        FileList = [System.Collections.ArrayList]@()
                    }

                    $progressId = [Math]::Abs(($env:COMPUTERNAME).GetHashCode())

                    Write-Progress -Activity $Activity -Id $progressId

                    $sw = New-Object System.Diagnostics.Stopwatch
                    $sw.Start()

                    for ( $i = 0; $i -lt $files.Count; ++$i ) {
                        if ($sw.ElapsedMilliseconds -gt 1000) {
                            Write-Progress -Activity $Activity -Status "$i / $($files.Count)" -PercentComplete ($i * 100 / $files.Count) -Id $progressId
                            $sw.Restart()
                        }

                        if ( ( Test-Path $files[$i] ) -and ( Select-String -Path $files[$i] -Pattern "ServerInfo~" -Quiet ) ) {
                            [Void]$allResults.FileList.Add( $files[$i] )

                            Import-Csv -Path $files[$i] -ErrorAction SilentlyContinue |
                                Where-Object { $_.AnchorMailbox -like 'ServerInfo~*/*' -and $_.AnchorMailbox -notlike 'ServerInfo~*/autodiscover*' -and $_.AnchorMailbox -notlike 'ServerInfo~localhost*/*' } |
                                Select-Object -Property $outProps |
                                ForEach-Object {
                                    [Void]$allResults.Hits.Add( $_ )
                                }
                        }
                    }

                    Write-Progress -Activity $Activity -Id $progressId -Completed

                    return $allResults
                }

                function Get-Cve26857 {
                    [CmdletBinding()]
                    param ()
                    try {
                        Get-WinEvent -FilterHashtable @{
                            LogName      = 'Application'
                            ProviderName = 'MSExchange Unified Messaging'
                            Level        = '2'
                        } -ErrorAction SilentlyContinue | Where-Object Message -Like "*System.InvalidCastException*"
                    } catch {
                        Write-Host "  MSExchange Unified Messaging provider is not present or events not found in the Application Event log"
                    }
                }

                function Get-Cve26858 {
                    [CmdletBinding()]
                    param ()

                    $exchangePath = Get-ExchangeInstallPath
                    if ($null -eq $exchangePath) {
                        Write-Host "  Exchange 2013 or later not found. Skipping CVE-2021-26858 test."
                        return
                    }

                    $allResults = @{
                        downloadPaths = [System.Collections.ArrayList]@()
                        filePaths     = [System.Collections.ArrayList]@()
                    }

                    $files = [System.Array](Get-ChildItem -Recurse -Path "$exchangePath\Logging\OABGeneratorLog" | Select-String "Download failed and temporary file" -List | Select-Object -ExpandProperty Path)

                    for ( $i = 0; $i -lt $files.Count; $i++) {
                        $maliciousPathFound = $false
                        $logInstance = Select-String -Path $files[$i] -Pattern "Download failed and temporary file"
                        foreach ($logLine in $logInstance) {
                            $path = ([String]$logLine | Select-String -Pattern 'Download failed and temporary file (.*?) needs to be removed').Matches.Groups[1].value
                            if ($null -ne $path -and (-not ($path.StartsWith("'$exchangePath" + "ClientAccess\OAB", "CurrentCultureIgnoreCase")))) {
                                [Void]$allResults.downloadPaths.Add( [String]$path )
                                $maliciousPathFound = $true
                            }
                        }
                        if ($maliciousPathFound) {
                            $allResults.FilePaths.Add([String]$files[$i])
                        }
                    }
                    return $allResults
                }

                function Get-Cve27065 {
                    [CmdletBinding()]
                    param ()

                    $exchangePath = Get-ExchangeInstallPath

                    $outProps = @(
                        "DateTime", "RequestId", "ClientIPAddress", "UrlHost",
                        "UrlStem", "RoutingHint", "UserAgent", "AnchorMailbox",
                        "HttpStatus"
                    )

                    $files = [System.Array](Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Ecp" -Filter '*.log').FullName
                    $allResults = @{
                        resetVDirHits           = [System.Collections.ArrayList]@()
                        resetVDirFiles          = [System.Collections.ArrayList]@()
                        setVDirMaliciousUrlLogs = [System.Collections.ArrayList]@()
                    }
                    for ( $i = 0; $i -lt $files.Count; ++$i ) {

                        if ((Get-ChildItem $files[$i] -ErrorAction SilentlyContinue | Select-String -Pattern "ServerInfo~").Count -gt 0) {

                            $hits = @(Import-Csv -Path $files[$i] -ErrorAction SilentlyContinue | Where-Object { $_.AnchorMailbox -like 'ServerInfo~*/*Reset*VirtualDirectory#' -and $_.HttpStatus -eq 200 } |
                                    Select-Object -Property $outProps)
                            if ($hits.Count -gt 0) {
                                $hits | ForEach-Object {
                                    [Void]$allResults.resetVDirHits.Add( $_ )
                                }
                                [Void]$allResults.resetVDirFiles.Add( $files[$i] )
                            }
                        }
                    }
                    $allResults.setVDirMaliciousUrlLogs = Get-ChildItem -Recurse -Path "$exchangePath\Logging\ECP\Server\*.log" -ErrorAction SilentlyContinue | Select-String "Set-.+VirtualDirectory.+?(?=Url).+<\w+.*>(.*?)<\/\w+>.+?(?=VirtualDirectory)" -List | Select-Object -ExpandProperty Path
                    return $allResults
                }

                function Get-SuspiciousFile {
                    [CmdletBinding()]
                    param ()

                    $zipFilter = ".7z", ".zip", ".rar"
                    $dmpFilter = "lsass.*dmp"
                    $dmpPaths = "c:\root", "$env:WINDIR\temp"

                    Get-ChildItem -Path $dmpPaths -Filter $dmpFilter -Recurse -ErrorAction SilentlyContinue |
                        ForEach-Object {
                            [PSCustomObject]@{
                                ComputerName = $env:COMPUTERNAME
                                Type         = 'LsassDump'
                                Path         = $_.FullName
                                Name         = $_.Name
                                LastWrite    = $_.LastWriteTimeUtc
                            }
                        }

                    Get-ChildItem -Path $env:ProgramData -Recurse -ErrorAction SilentlyContinue |
                        ForEach-Object {
                            if ( $_.Extension -in $zipFilter ) {
                                [PSCustomObject]@{
                                    ComputerName = $env:COMPUTERNAME
                                    Type         = 'SuspiciousArchive'
                                    Path         = $_.FullName
                                    Name         = $_.Name
                                    LastWrite    = $_.LastWriteTimeUtc
                                }
                            }
                        }
                }

                function Get-AgeInDays {
                    param ( $dateString )
                    if ( $dateString -and $dateString -as [DateTime] ) {
                        $CurTime = Get-Date
                        $age = $CurTime.Subtract($dateString)
                        return $age.TotalDays.ToString("N1")
                    }
                    return ""
                }

                function Get-LogAge {
                    [CmdletBinding()]
                    param ()

                    $exchangePath = Get-ExchangeInstallPath
                    if ($null -eq $exchangePath) {
                        Write-Host "  Exchange 2013 or later not found. Skipping log age checks."
                        return $null
                    }

                    [PSCustomObject]@{
                        OabGen           = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\OABGeneratorLog" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        Ecp              = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\ECP\Server\*.log" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        AutoDProxy       = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Autodiscover" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        EasProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Eas" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        EcpProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Ecp" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        EwsProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Ews" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        MapiProxy        = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Mapi" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        OabProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Oab" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        OwaProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Owa" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        OwaCalendarProxy = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\OwaCalendar" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        PowershellProxy  = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\PowerShell" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        RpcHttpProxy     = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\RpcHttp" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                    }
                }
                #end region Functions

                $results = [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    Cve26855     = Get-Cve26855
                    Cve26857     = @(Get-Cve26857)
                    Cve26858     = Get-Cve26858
                    Cve27065     = Get-Cve27065
                    LogAgeDays   = Get-LogAge
                    IssuesFound  = $false
                    Suspicious   = $null
                }

                if ($results.Cve26855.Hits.Count -or $results.Cve26857.Count -or $results.Cve26858.downloadPaths.Count -or $results.Cve27065.resetVDirHits.Count -or $results.Cve27065.setVDirMaliciousUrlLogs.Count) {
                    $results.Suspicious = @(Get-SuspiciousFile)
                    $results.IssuesFound = $true
                }

                $results
            }
            #end region Remoting Scriptblock
            $parameters = @{
                ScriptBlock = $scriptBlock
            }
            if ($Credential) { $parameters['Credential'] = $Credential }
        }
        process {
            if ($null -ne $ComputerName) {
                Invoke-Command @parameters -ComputerName $ComputerName
            } else {
                Invoke-Command @parameters
            }
        }
    }

    function Write-ProxyLogonReport {
        <#
    .SYNOPSIS
        Processes output of Test-ExchangeProxyLogon for reporting on the console screen.

    .DESCRIPTION
        Processes output of Test-ExchangeProxyLogon for reporting on the console screen.

    .PARAMETER InputObject
        The reports provided by Test-ExchangeProxyLogon

    .PARAMETER OutPath
        Path to a FOLDER in which to generate output LogFiles.
        This command will only write to the console screen if no path is provided.

    .EXAMPLE
        PS C:\> Test-ExchangeProxyLogon -ComputerName (Get-ExchangeServer).Fqdn | Write-ProxyLogonReport -OutPath C:\logs

        Gather data from all exchange servers in the organization and write a report to C:\logs
#>
        [CmdletBinding()]
        param (
            [parameter(ValueFromPipeline = $true)]
            $InputObject,

            [string]
            $OutPath = "$PSScriptRoot\Test-ProxyLogonLogs",

            [switch]
            $DisplayOnly,

            [switch]
            $CollectFiles
        )

        begin {
            if ($OutPath -and -not $DisplayOnly) {
                New-Item $OutPath -ItemType Directory -Force | Out-Null
            }
        }

        process {
            foreach ($report in $InputObject) {

                $isLocalMachine = $report.ComputerName -eq $env:COMPUTERNAME

                if ($CollectFiles) {
                    $LogFileOutPath = $OutPath + "\CollectedLogFiles\" + $report.ComputerName
                    if (-not (Test-Path -Path $LogFileOutPath)) {
                        New-Item $LogFileOutPath -ItemType Directory -Force | Out-Null
                    }
                }

                Write-Host "ProxyLogon Status: Exchange Server $($report.ComputerName)"

                if ($null -ne $report.LogAgeDays) {
                    Write-Host ("  Log age days: OabGen {0} Ecp {1} AutoD {2} Eas {3} EcpProxy {4} Ews {5} Mapi {6} Oab {7} Owa {8} OwaCal {9} Powershell {10} RpcHttp {11}" -f `
                            $report.LogAgeDays.OabGen, `
                            $report.LogAgeDays.Ecp, `
                            $report.LogAgeDays.AutoDProxy, `
                            $report.LogAgeDays.EasProxy, `
                            $report.LogAgeDays.EcpProxy, `
                            $report.LogAgeDays.EwsProxy, `
                            $report.LogAgeDays.MapiProxy, `
                            $report.LogAgeDays.OabProxy, `
                            $report.LogAgeDays.OwaProxy, `
                            $report.LogAgeDays.OwaCalendarProxy, `
                            $report.LogAgeDays.PowershellProxy, `
                            $report.LogAgeDays.RpcHttpProxy)

                    if (-not $DisplayOnly) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-LogAgeDays.csv"
                        $report.LogAgeDays | Export-Csv -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    }
                }

                if (-not $report.IssuesFound) {
                    Write-Host "  Nothing suspicious detected" -ForegroundColor Green
                    Write-Host ""
                    continue
                }
                if ($report.Cve26855.Hits.Count -gt 0) {
                    Write-Host "  [CVE-2021-26855] Suspicious activity found in Http Proxy log!" -ForegroundColor Red
                    if (-not $DisplayOnly) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-26855.csv"
                        $report.Cve26855.Hits | Export-Csv -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    } else {
                        $report.Cve26855.Hits | Format-Table DateTime, AnchorMailbox -AutoSize | Out-Host
                    }
                    if ($CollectFiles -and $isLocalMachine) {
                        Write-Host " Copying Files:"
                        if (-not (Test-Path -Path "$($LogFileOutPath)\CVE26855")) {
                            Write-Host " Creating CVE26855 Collection Directory"
                            New-Item "$($LogFileOutPath)\CVE26855" -ItemType Directory -Force | Out-Null
                        }
                        foreach ($entry in $report.Cve26855.FileList) {
                            if (Test-Path -Path $entry) {
                                Write-Host "  Copying $($entry) to $($LogFileOutPath)\CVE26855" -ForegroundColor Green
                                Copy-Item -Path $entry -Destination "$($LogFileOutPath)\CVE26855"
                            } else {
                                Write-Host "  Warning: Unable to copy file $($entry). File does not exist." -ForegroundColor Red
                            }
                        }
                    }
                    Write-Host ""
                }
                if ($report.Cve26857.Count -gt 0) {
                    Write-Host "  [CVE-2021-26857] Suspicious activity found in Eventlog!" -ForegroundColor Red
                    Write-Host "  $(@($report.Cve26857).Count) events found"
                    if (-not $DisplayOnly) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-26857.csv"
                        $report.Cve26857 | Select-Object TimeCreated, MachineName, Message | Export-Csv -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    }

                    if ($CollectFiles -and $isLocalMachine) {
                        Write-Host "`n`r Copying Application Event Log"
                        if (-not (Test-Path -Path "$($LogFileOutPath)\CVE26857")) {
                            Write-Host "  Creating CVE26857 Collection Directory"
                            New-Item "$($LogFileOutPath)\CVE26857" -ItemType Directory -Force | Out-Null
                        }

                        Start-Process wEvtUtil -ArgumentList "epl Software $($LogFileOutPath)\CVE26857\Application.evtx"
                    }
                    Write-Host ""
                }
                if ($report.Cve26858.downloadPaths.Count -gt 0) {
                    Write-Host "  [CVE-2021-26858] Suspicious activity found in OAB generator logs!" -ForegroundColor Red
                    Write-Host "  WebShells possibly downloaded in file system. Explore below locations:" -ForegroundColor Red
                    if (-not $DisplayOnly) {
                        $newFileDownloadPaths = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-26858-DownloadPaths.log"
                        $newFileForFilePaths = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-26858.log"
                        $report.Cve26858.downloadPaths | Set-Content -Path $newFileDownloadPaths
                        $report.Cve26858.filePaths | Set-Content -Path $newFileForFilePaths
                        Write-Host "  Report exported to: $newFileForFilePaths"
                        Write-Host "  Report exported to: $newFileDownloadPaths"
                    } else {
                        $report.Cve26858.downloadPaths | Out-Host
                    }
                    if ($CollectFiles -and $isLocalMachine) {
                        Write-Host " Copying Files:"
                        if (-not (Test-Path -Path "$($LogFileOutPath)\CVE26858")) {
                            Write-Host " Creating CVE26858 Collection Directory"
                            New-Item "$($LogFileOutPath)\CVE26858" -ItemType Directory -Force | Out-Null
                        }
                        foreach ($entry in $report.Cve26858.filePaths) {
                            if (Test-Path -Path $entry) {
                                Write-Host "  Copying $($entry) to $($LogFileOutPath)\CVE26858" -ForegroundColor Green
                                Copy-Item -Path $entry -Destination "$($LogFileOutPath)\CVE26858"
                            } else {
                                Write-Host "  Warning: Unable to copy file $($entry). File does not exist." -ForegroundColor Red
                            }
                        }
                    }
                    Write-Host ""
                }
                if ($report.Cve27065.setVDirMaliciousUrlLogs.Count -gt 0) {
                    Write-Host "  [CVE-2021-27065] Suspicious activity found in ECP logs!" -ForegroundColor Red
                    Write-Host "  Please review the following files for 'Set-*VirtualDirectory' entries (potentially malicious urls used):"
                    foreach ($entry in $report.Cve27065.setVDirMaliciousUrlLogs) {
                        Write-Host "   $entry"
                        if ($CollectFiles -and $isLocalMachine) {
                            Write-Host " Copying Files:"
                            if (-not (Test-Path -Path "$($LogFileOutPath)\CVE27065")) {
                                Write-Host " Creating CVE27065 Collection Directory"
                                New-Item "$($LogFileOutPath)\CVE27065" -ItemType Directory -Force | Out-Null
                            }
                            if (Test-Path -Path $entry) {
                                Write-Host "  Copying $($entry) to $($LogFileOutPath)\CVE27065" -ForegroundColor Green
                                Copy-Item -Path $entry -Destination "$($LogFileOutPath)\CVE27065"
                            } else {
                                Write-Host "  Warning: Unable to copy file $($entry.Path). File does not exist." -ForegroundColor Red
                            }
                        }
                    }
                    if (-not $DisplayOnly) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-27065.log"
                        $report.Cve27065.setVDirMaliciousUrlLogs | Set-Content -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    }
                    Write-Host ""
                }
                if ($report.Cve27065.resetVDirHits.Count -gt 0) {
                    Write-Host "  [CVE-2021-27065] WebShell possibly downloaded in file system" -ForegroundColor Red
                    Write-Host "  Please scan your file system for any malicious WebShells. Reset-VirtualDirectory entries:"
                    if (-not $DisplayOnly) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-27065-ResetVDir.csv"
                        $report.Cve27065.resetVDirHits | Export-Csv -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    } else {
                        $report.Cve27065.resetVDirHits | Format-Table DateTime, AnchorMailbox -AutoSize | Out-Host
                    }
                    if ($CollectFiles -and $isLocalMachine) {
                        Write-Host " Copying Files:"
                        if (-not (Test-Path -Path "$($LogFileOutPath)\Cve27065")) {
                            Write-Host " Creating Cve27065 Collection Directory"
                            New-Item "$($LogFileOutPath)\Cve27065" -ItemType Directory -Force | Out-Null
                        }
                        foreach ($entry in $report.Cve27065.resetVDirFiles) {
                            if (Test-Path -Path $entry) {
                                Write-Host "  Copying $($entry) to $($LogFileOutPath)\Cve27065" -ForegroundColor Green
                                Copy-Item -Path $entry -Destination "$($LogFileOutPath)\Cve27065"
                            } else {
                                Write-Host "  Warning: Unable to copy file $($entry). File does not exist." -ForegroundColor Red
                            }
                        }
                    }
                    Write-Host ""
                }
                if ($report.Suspicious.Count -gt 0) {
                    Write-Host "  Other suspicious files found: $(@($report.Suspicious).Count)"
                    if (-not $DisplayOnly) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-other.csv"
                        $report.Suspicious | Export-Csv -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    } else {
                        foreach ($entry in $report.Suspicious) {
                            Write-Host "   $($entry.Type) : $($entry.Path)"
                        }
                    }
                    if ($CollectFiles -and $isLocalMachine) {
                        Write-Host " Copying Files:"

                        #Deleting and recreating suspiciousFiles folder to prevent overwrite exceptions due to folders (folder name: MyFolder.zip)
                        if ( Test-Path -Path "$($LogFileOutPath)\SuspiciousFiles" ) {
                            Remove-Item -Path "$($LogFileOutPath)\SuspiciousFiles" -Recurse -Force
                        }
                        Write-Host "  Creating SuspiciousFiles Collection Directory"
                        New-Item "$($LogFileOutPath)\SuspiciousFiles" -ItemType Directory -Force | Out-Null

                        $fileNumber = 0
                        foreach ($entry in $report.Suspicious) {
                            if (Test-Path -Path $entry.path) {
                                Write-Host "  Copying $($entry.Path) to $($LogFileOutPath)\SuspiciousFiles" -ForegroundColor Green
                                Copy-Item -Path $entry.Path -Destination "$($LogFileOutPath)\SuspiciousFiles\$($entry.Name)_$fileNumber"
                                $fileNumber += 1
                            } else {
                                Write-Host "  Warning: Unable to copy file $($entry.Path). File does not exist." -ForegroundColor Red
                            }
                        }
                    }
                }
            }
        }
    }
    #end region Functions

    $paramTest = @{ }
    if ($Credential) { $paramTest['Credential'] = $Credential }
    $paramWrite = @{
        OutPath = $OutPath
    }
    if ($CollectFiles) { $paramWrite['CollectFiles'] = $true }
    if ($DisplayOnly) {
        $paramWrite = @{ DisplayOnly = $true }
    }

    $computerTargets = New-Object System.Collections.ArrayList
}
process {

    if ($Export) {
        Set-Item function:global:Test-ExchangeProxyLogon (Get-Command Test-ExchangeProxyLogon)
        Set-Item function:global:Write-ProxyLogonReport (Get-Command Write-ProxyLogonReport)
        return
    }

    # Gather up computer targets as they are piped into the command.
    # Passing them to Test-ExchangeProxyLogon in one batch ensures parallel processing
    foreach ($computer in $ComputerName) {
        $null = $computerTargets.Add($computer)
    }
}
end {
    if ($Export) { return }

    if ($computerTargets.Length -lt 1) {
        Test-ExchangeProxyLogon @paramTest | Write-ProxyLogonReport @paramWrite
    } else {
        Test-ExchangeProxyLogon -ComputerName $computerTargets.ToArray() @paramTest | Write-ProxyLogonReport @paramWrite
    }
}

# SIG # Begin signature block
# MIIoDAYJKoZIhvcNAQcCoIIn/TCCJ/kCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDKwoxoPwlNgzUC
# WMp042n1+VgXCEb2xgkGYMtOVu3TAKCCDXYwggX0MIID3KADAgECAhMzAAAEBGx0
# Bv9XKydyAAAAAAQEMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjQwOTEyMjAxMTE0WhcNMjUwOTExMjAxMTE0WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC0KDfaY50MDqsEGdlIzDHBd6CqIMRQWW9Af1LHDDTuFjfDsvna0nEuDSYJmNyz
# NB10jpbg0lhvkT1AzfX2TLITSXwS8D+mBzGCWMM/wTpciWBV/pbjSazbzoKvRrNo
# DV/u9omOM2Eawyo5JJJdNkM2d8qzkQ0bRuRd4HarmGunSouyb9NY7egWN5E5lUc3
# a2AROzAdHdYpObpCOdeAY2P5XqtJkk79aROpzw16wCjdSn8qMzCBzR7rvH2WVkvF
# HLIxZQET1yhPb6lRmpgBQNnzidHV2Ocxjc8wNiIDzgbDkmlx54QPfw7RwQi8p1fy
# 4byhBrTjv568x8NGv3gwb0RbAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQU8huhNbETDU+ZWllL4DNMPCijEU4w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMjkyMzAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAIjmD9IpQVvfB1QehvpC
# Ge7QeTQkKQ7j3bmDMjwSqFL4ri6ae9IFTdpywn5smmtSIyKYDn3/nHtaEn0X1NBj
# L5oP0BjAy1sqxD+uy35B+V8wv5GrxhMDJP8l2QjLtH/UglSTIhLqyt8bUAqVfyfp
# h4COMRvwwjTvChtCnUXXACuCXYHWalOoc0OU2oGN+mPJIJJxaNQc1sjBsMbGIWv3
# cmgSHkCEmrMv7yaidpePt6V+yPMik+eXw3IfZ5eNOiNgL1rZzgSJfTnvUqiaEQ0X
# dG1HbkDv9fv6CTq6m4Ty3IzLiwGSXYxRIXTxT4TYs5VxHy2uFjFXWVSL0J2ARTYL
# E4Oyl1wXDF1PX4bxg1yDMfKPHcE1Ijic5lx1KdK1SkaEJdto4hd++05J9Bf9TAmi
# u6EK6C9Oe5vRadroJCK26uCUI4zIjL/qG7mswW+qT0CW0gnR9JHkXCWNbo8ccMk1
# sJatmRoSAifbgzaYbUz8+lv+IXy5GFuAmLnNbGjacB3IMGpa+lbFgih57/fIhamq
# 5VhxgaEmn/UjWyr+cPiAFWuTVIpfsOjbEAww75wURNM1Imp9NJKye1O24EspEHmb
# DmqCUcq7NqkOKIG4PVm3hDDED/WQpzJDkvu4FrIbvyTGVU01vKsg4UfcdiZ0fQ+/
# V0hf8yrtq9CkB8iIuk5bBxuPMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGewwghnoAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAAQEbHQG/1crJ3IAAAAABAQwDQYJYIZIAWUDBAIB
# BQCggZAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwLwYJKoZIhvcNAQkEMSIE
# IGrEXkDqqJ3jRJwlUh9N7cjUCAsgACasPTPb3XR204VlMEIGCisGAQQBgjcCAQwx
# NDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20wDQYJKoZIhvcNAQEBBQAEggEAgvAiUi4iv4v0rMjf1MQdIw6UtNJzM/87
# SYv2AL7bq9IL6DgAfIDGZAPhMDIHhvNzpb7t9QAGHXadeKGrqQSV3Vti3KvxJ6So
# XUNk4OaiDM2NsHXVmK/gaUDHM5FIbO0A3Jqdstg6dO8as5qnQZgowM1IR+rKwLkp
# 17IhFlf77mYhTpcU3ilYgXp5DVYK1wNsCE/1Yqq5YjEE4RIu2wV6bj0mYBd1NATJ
# va0Bn2pjdk5FljZZhcwlIuRVfxxvifzJM4EWmj03Upst7UTyMtcahFyNm3ex56tN
# h6wNJnluDgCT3gnKLdRmC2Q6YmaRARabSvuFWQSc1Hm1X6ImZjlp9KGCF5QwgheQ
# BgorBgEEAYI3AwMBMYIXgDCCF3wGCSqGSIb3DQEHAqCCF20wghdpAgEDMQ8wDQYJ
# YIZIAWUDBAIBBQAwggFSBgsqhkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYB
# BAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCBEQpOxR44frlktDmxv92ExQ/mPwa+j
# UPRmf9+BM1yUawIGZ/ft3Q7aGBMyMDI1MDQzMDE5NDA0MC43MjFaMASAAgH0oIHR
# pIHOMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYD
# VQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hp
# ZWxkIFRTUyBFU046ODYwMy0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2WgghHqMIIHIDCCBQigAwIBAgITMwAAAgcsETmJzYX7
# xQABAAACBzANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMDAeFw0yNTAxMzAxOTQyNTJaFw0yNjA0MjIxOTQyNTJaMIHLMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQg
# QW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046ODYw
# My0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZp
# Y2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDFP/96dPmcfgODe3/n
# uFveuBst/JmSxSkOn89ZFytHQm344iLoPqkVws+CiUejQabKf+/c7KU1nqwAmmti
# PnG8zm4Sl9+RJZaQ4Dx3qtA9mdQdS7Chf6YUbP4Z++8laNbTQigJoXCmzlV34vmC
# 4zpFrET4KAATjXSPK0sQuFhKr7ltNaMFGclXSnIhcnScj9QUDVLQpAsJtsKHyHN7
# cN74aEXLpFGc1I+WYFRxaTgqSPqGRfEfuQ2yGrAbWjJYOXueeTA1MVKhW8zzSEpf
# jKeK/t2XuKykpCUaKn5s8sqNbI3bHt/rE/pNzwWnAKz+POBRbJxIkmL+n/EMVir5
# u8uyWPl1t88MK551AGVh+2H4ziR14YDxzyCG924gaonKjicYnWUBOtXrnPK6AS/L
# N6Y+8Kxh26a6vKbFbzaqWXAjzEiQ8EY9K9pYI/KCygixjDwHfUgVSWCyT8Kw7mGB
# yUZmRPPxXONluMe/P8CtBJMpuh8CBWyjvFfFmOSNRK8ETkUmlTUAR1CIOaeBqLGw
# scShFfyvDQrbChmhXib4nRMX5U9Yr9d7VcYHn6eZJsgyzh5QKlIbCQC/YvhFK42c
# eCBDMbc+Ot5R6T/Mwce5jVyVCmqXVxWOaQc4rA2nV7onMOZC6UvCG8LGFSZBnj1l
# oDDLWo/I+RuRok2j/Q4zcMnwkQIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFHK1UmLC
# vXrQCvR98JBq18/4zo0eMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1Gely
# MF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lv
# cHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNy
# bDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBD
# QSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQDju0quPbni
# x0slEjD7j2224pYOPGTmdDvO0+bNRCNkZqUv07P04nf1If3Y/iJEmUaU7w12Fm58
# 2ImpD/Kw2ClXrNKLPTBO6nfxvOPGtalpAl4wqoGgZxvpxb2yEunG4yZQ6EQOpg1d
# E9uOXoze3gD4Hjtcc75kca8yivowEI+rhXuVUWB7vog4TGUxKdnDvpk5GSGXnOhP
# DhdId+g6hRyXdZiwgEa+q9M9Xctz4TGhDgOKFsYxFhXNJZo9KRuGq6evhtyNduYr
# kzjDtWS6gW8akR59UhuLGsVq+4AgqEY8WlXjQGM2OTkyBnlQLpB8qD7x9jRpY2Cq
# 0OWWlK0wfH/1zefrWN5+be87Sw2TPcIudIJn39bbDG7awKMVYDHfsPJ8ZvxgWkZu
# f6ZZAkph0eYGh3IV845taLkdLOCvw49Wxqha5Dmi2Ojh8Gja5v9kyY3KTFyX3T4C
# 2scxfgp/6xRd+DGOhNVPvVPa/3yRUqY5s5UYpy8DnbppV7nQO2se3HvCSbrb+yPy
# eob1kUfMYa9fE2bEsoMbOaHRgGji8ZPt/Jd2bPfdQoBHcUOqPwjHBUIcSc7xdJZY
# jRb4m81qxjma3DLjuOFljMZTYovRiGvEML9xZj2pHRUyv+s5v7VGwcM6rjNYM4qz
# ZQM6A2RGYJGU780GQG0QO98w+sucuTVrfTCCB3EwggVZoAMCAQICEzMAAAAVxedr
# ngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRp
# ZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4
# MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3
# DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qls
# TnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLA
# EBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrE
# qv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyF
# Vk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1o
# O5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg
# 3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2
# TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07B
# MzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJ
# NmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6
# r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+
# auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3
# FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl
# 0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUH
# AgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0
# b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMA
# dQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAW
# gBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8v
# Y3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRf
# MjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEw
# LTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL
# /Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu
# 6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5t
# ggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfg
# QJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8s
# CXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCr
# dTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZ
# c9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2
# tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8C
# wYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9
# JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDB
# cQZqELQdVTNYs6FwZvKhggNNMIICNQIBATCB+aGB0aSBzjCByzELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFt
# ZXJpY2EgT3BlcmF0aW9uczEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjg2MDMt
# MDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oiMKAQEwBwYFKw4DAhoDFQDTvVU/Yj9lUSyeDCaiJ2Da5hUiS6CBgzCBgKR+MHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA67zI
# ojAiGA8yMDI1MDQzMDE2MDQ1MFoYDzIwMjUwNTAxMTYwNDUwWjB0MDoGCisGAQQB
# hFkKBAExLDAqMAoCBQDrvMiiAgEAMAcCAQACAgOjMAcCAQACAhPfMAoCBQDrvhoi
# AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSCh
# CjAIAgEAAgMBhqAwDQYJKoZIhvcNAQELBQADggEBAFpX6iHF5iSDZSV9MsGkIaEe
# c5OApKbteNtQojR5ve1Ls2qR+ugUJN7y2zy69imAMQuvgP8bHnucAAfcfcV5OvWi
# guUykuoVbt2HJ3X+lz+AzxUgDGPA/gRcSk3OvXyzgfTED7LSR2qaShzzKMzIs8QN
# M+W78YarqXeYRJE0ofpU35rb1oRnnMLoYfD12lqXKycZyg0qsR/apko6McUITINU
# MDGa91kloXBzhjOR02Ud2xv+rHawvrCu6BYz/y4NCZVgd8X/PPkB6squUyorWtBP
# H0TTN86QF5NsWy9uGm+WyOGMUnnYvYqkyJv17svNDJKHg6slNCyDHyuo/WKig9Qx
# ggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# AgcsETmJzYX7xQABAAACBzANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkD
# MQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCCkfS0QfHSYr41SSFsDC0cX
# QqLMcnJDlBQ7bNOWKDtZxDCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIC/3
# 1NHQds1IZ5sPnv59p+v6BjBDgoDPIwiAmn0PHqezMIGYMIGApH4wfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAIHLBE5ic2F+8UAAQAAAgcwIgQgjhRo
# yXBt/eV0aHPYo0Fcfu/EO5QGse9HcXw8ZlYt17IwDQYJKoZIhvcNAQELBQAEggIA
# XFKwGiLvNp+h8G2SsTvTBNB1OYcUU+TmU1E4MPus9V2SH/scVVyq1FRQKrCJEuW/
# Zp585MyqkLSKYYdCixBxHuDlS1MdGSXpMQQUVzHVjf+ofc7o7k9YjbEVoR3lDxmM
# MxWKqyDRMrkqn2wENQvNb0REderfwvzRPT3FGIIoj39a+zVQO6OXM8RtLgaH4BHZ
# OXR1hLHOK8xJmRAStFXlOnBAjovBkSPJiAozslw0c/zf/w1S2t3oyreGkDzIsJDn
# CR21H+p0XQFLCYIv5Dp7T15eKdofEdUtlvxYffcI5B9/Es03afGupniNJ0UJW/iV
# JcSQDc/cYMQyIMoN0nmS6bwWv1V5rpO0GFm6sFTm+rcnOEXjeLOEJvyTUz2436/W
# fMW2yDwovUfXw5c/Ji7sWM+2pgQZFvK+kkxNn2ZeOex3npH1UGWIytKS2RyKdk4l
# 77F8Yvd7S/3kbuCL3hAHAv4w2QgDY/NBTOO+vBbg2nxwQv76VGOuphxQFLlOIczB
# ysyGsv6ceiWk/CbRjLrwb1v9VhIqgncsXgb74fNZ7pSaNa7gAxSCb8Pf2661khYD
# Oo6Nu2EMAQdlX5a6sPdZbS+WtQDCgBtSjXq8pgSxozVGfz84Sq4JHEqvRDvdWz0M
# RUCB7Q8yYY6A1bJoRHiDqcdP37/+bToY+OXlGEPa5XE=
# SIG # End signature block
```
