################################ RUN/RUNONCE #############################

# Define Run and RunOnce paths
$runAndRunOncePaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

$runAndRunOnceResult = @();
$errors = @();

foreach ($registryPath in $runAndRunOncePaths) {
    if (Test-Path $registryPath) {
        # Get all properties (values) in the registry key
        $properties = Get-ItemProperty -Path $registryPath

        # Filter out PowerShell internal properties
        $propertyNames = $properties.PSObject.Properties.Name | Where-Object {
            $_ -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')
        }

        # Create a hashtable for JSON conversion
        $data = @{}
        foreach ($name in $propertyNames) {
            $data[$name] = $properties.$name
        }

        # Convert to JSON format
        $json = $data | ConvertTo-Json -Depth 5

        # Append to the result
        $runAndRunOnceResult += $json;
    } else {
        $errors += "Error for path" + $registryPath | ConvertTo-Json -Depth 5;
    }
}

Write-Output $runAndRunOnceResult;
Write-Output $errors;






####################################### Browser Extensions ##########################################
# Get current user profile
$userProfile = [Environment]::GetFolderPath("UserProfile")

$chromiumPaths = @{
    'GoogleChrome' = "AppData\Local\Google\Chrome\User Data\Default\Extensions"
    'MicrosoftEdge' = "AppData\Local\Microsoft\Edge\User Data\Default\Extensions"
    'Brave'="AppData\Local\BraveSotware\Brave-Browser\User Data\Default\Extensions"
    'Opera' = "AppData\Roaming\Opera Software\Opera Stable\Extensions"
}

foreach ($key in $chromiumPaths.Keys) {

    # Define base extensions path
    #$extensionsPath = Join-Path $userProfile "AppData\Local\Google\Chrome\User Data\Default\Extensions"
    $extensionsPath = Join-Path $userProfile $chromiumPaths[$key]

    # Check if the directory exists
    if (-not (Test-Path $extensionsPath)) {
        Write-Host "$key extensions directory not found: $extensionsPath"
    }

    Write-Host "Scanning $key extensions for manifests..."
    Write-Host "Path: $extensionsPath"

    # Recursively find all manifest.json files two levels deep
    $manifestFiles = Get-ChildItem -Path $extensionsPath -Recurse -Filter "manifest.json" -ErrorAction SilentlyContinue

    foreach ($manifest in $manifestFiles) {
        try {
            # Read and parse JSON content
            $jsonContent = Get-Content -Path $manifest.FullName -Raw | ConvertFrom-Json

            # Get extension name if present
            $extensionName = $jsonContent.name
            if ($extensionName) {
                Write-Output "$extensionName — $($manifest.Directory.FullName)"
            } else {
                Write-Output "No 'name' key found in: $($manifest.FullName)"
            }
        }
        catch {
            Write-Output "Error reading JSON: $($manifest.FullName)"
        }
    }
    Write-Output "-----------------------------------------------------------"
}



##################################### Office Add Ins ####################################
$officeAddInRegistryPath = "HKCU:\SOFTWARE\Microsoft\Office";
$addIns = @();

Get-ChildItem $officeAddInRegistryPath -Recurse | 
    Where-Object { $_.Name -like "*Addins*" } |
    ForEach-Object {
        $manifest = (Get-ItemProperty $_.PsPath -ErrorAction SilentlyContinue).Manifest
        if ($manifest) {
            $addIn = [PSCustomObject]@{
                AddinName = Split-Path $_.PsPath -Leaf
                Manifest  = $manifest
            }
            $addIns += $addIn;
        }
    }

Write-Output $addIns


############################# 
