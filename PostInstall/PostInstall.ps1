[net.servicepointmanager]::securityprotocol = "tls12" 

function progresswriter{
    param (
        [int]$percentcomplete,
        [string]$status
    )
    write-progress -activity "Setting Up Your Machine" -status $status -percentcomplete $percentcomplete
}

function logger($event){
    $event.exception.message | out-file "c:\cloud_prep.log" -append
}

#Creating Folders and moving script files into System directories
function setup-environment{
    progressWriter -status "Moving files and folders into place" -percentcomplete $percentcomplete
    new-item -path c:\parsectemp\apps -itemtype directory | out-null
    new-item -path c:\parsectemp\drivers -itemtype directory | out-null
}

#download-T4-GRID-driver
function download-resources{
    progresswriter -status "Downloading software and GRID Driver" -percentcomplete $percentcomplete
    
    # Download Parsec
    Invoke-WebRequest -Uri "https://builds.parsec.app/package/parsec-windows.exe" -OutFile "C:\ParsecTemp\Apps\parsec-windows.exe" -UseBasicParsing

    # Dynamically find and download the latest AWS NVIDIA Grid Driver via S3 REST API
    progresswriter -status "Fetching latest AWS NVIDIA GRID Driver" -percentcomplete $percentcomplete
    
    $s3Url = "https://ec2-windows-nvidia-drivers.s3.amazonaws.com"
    $rawXml = (Invoke-WebRequest -Uri "$s3Url/?prefix=latest/" -UseBasicParsing).Content
    
    # UPDATED REGEX: Catches the new "_aws_swl" tag or anything else AWS appends before the .exe
    $driverKey = [regex]::Match($rawXml, 'latest/[^<]+grid_win10_win11_server2019_server2022_dch_64bit[^<]*\.exe').Value
    
    # Failsafe just in case AWS drastically changes their naming convention again
    if ([string]::IsNullOrWhiteSpace($driverKey)) {
        throw "Failed to find the NVIDIA driver in the AWS bucket! The regex matched nothing."
    }

    $driverUrl = "$s3Url/$driverKey"
    
    # Download the exact driver
    Invoke-WebRequest -Uri $driverUrl -OutFile "c:\parsectemp\drivers\GRID_driver.exe" -UseBasicParsing
}

#set automatic time and timezone
function set-time {
    progresswriter -status "Setting computer time to automatic" -percentcomplete $percentcomplete
    set-itemproperty -path hklm:\system\currentcontrolset\services\w32time\parameters -name type -value ntp | out-null
    set-itemproperty -path hklm:\system\currentcontrolset\services\tzautoupdate -name start -value 00000003 | out-null
}
    
#Enable Pointer Precision 
function enhance-pointer-precision {
    progresswriter -status "Enabling enchanced pointer precision" -percentcomplete $percentcomplete
    set-itemproperty -path 'HKCU:\control panel\mouse' -name mousespeed -value 1 | out-null
}

#enable Mouse Keys
function enable-mouse-keys {
    progresswriter -status "Enabling mouse keys to assist with mouse cursor" -percentcomplete $percentcomplete
    set-itemproperty -path 'HKCU:\control panel\accessibility\mousekeys' -name flags -value 63 | out-null
}

#disable shutdown start menu
function remove-shutdown {
    write-output "Disabling Shutdown Option in Start Menu"
    new-itemproperty -path HKLM:\software\microsoft\windows\currentversion\policies\explorer -name noclose -value 1 | out-null
}

#7Zip is required to extract the GRID_Driver.exe file/driver files
function install7zip {
    progresswriter -status "Installing 7Zip" -percentcomplete $percentComplete
    
    # FIXED: Safely parsing the 7-Zip website for the 64-bit installer
    $url = Invoke-WebRequest -Uri "https://www.7-zip.org/download.html" -UseBasicParsing
    $href = ($url.Links | Where-Object { $_.href -match "x64\.exe" })[0].href
    
    # Account for absolute vs relative HTML links
    if ($href -match "^http") { $downloadUrl = $href }
    else { $downloadUrl = "https://www.7-zip.org/$href" }

    Invoke-WebRequest -Uri $downloadUrl -OutFile "c:\parsectemp\apps\7zip.exe" -UseBasicParsing
    Start-Process "c:\parsectemp\apps\7zip.exe" -ArgumentList '/S /D="c:\program files\7-zip"' -Wait
}

#install-graphics-driver
function install-graphics-driver {
    progresswriter -status "Installing 7Zip and GPU Driver" -percentcomplete $percentComplete
    install7zip
    cmd.exe /c '"c:\program files\7-zip\7z.exe" x c:\parsectemp\drivers\grid_driver.exe -oC:\parsectemp\drivers\grid_driver -y' | Out-Null
    cmd.exe /c "c:\parsectemp\drivers\grid_driver\setup.exe /s"
}

#install parsec
function install-parsec{
    progresswriter -status "Installing parsec" -percentcomplete $percentcomplete
    
    # Retrieve User Data using AWS IMDSv2
    $token = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token-ttl-seconds" = "21600"} -Method PUT -Uri "http://169.254.169.254/latest/api/token"
    $rawUserData = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token} -Method GET -Uri "http://169.254.169.254/latest/user-data"
    
    # Extract the JSON payload using Regex (since the AWS user data also contains the PowerShell wrapper)
    $jsonString = [regex]::Match($rawUserData, '(?s)\{\s*"data".*?\]\s*\}').Value
    if ([string]::IsNullOrWhiteSpace($jsonString)) {
        $jsonString = $rawUserData # Fallback in case user data is purely JSON
    }
    
    $decoded = $jsonString | convertfrom-json
    
    $arglist = "/silent /shared /vdd"
    $userassigned = $false
    foreach($setting in $decoded.data){
        if($setting.value){
            if($setting.setting -eq "user_email"){
                $userassigned = $true
            }
            elseif($setting.setting -eq "team_group_id" -and $userassigned -eq $true){
                continue
            }
            $arglist += (" /{0}={1}" -f $setting.setting, $setting.value)
        }
    }      
    start-process "c:\parsectemp\apps\parsec-windows.exe" -argumentlist $arglist -wait
    start-process -filepath "c:\program files\parsec\parsecd.exe"
    start-sleep -s 1
}

#Disable Devices
function disable-devices {
    progresswriter -status "Disabling Microsoft Basic Display Adapter, Generic Non PNP Monitor and other devices" -percentcomplete $percentcomplete
    get-pnpdevice | where-object {$_.friendlyname -like "Generic Non-PNP Monitor" -and $_.status -eq "OK"} | disable-pnpdevice -confirm:$false | out-null
    get-pnpdevice | where-object {$_.friendlyname -like "Microsoft Basic Display Adapter" -and $_.status -eq "OK"} | disable-pnpdevice -confirm:$false | out-null
    get-pnpdevice | where-object {$_.friendlyname -like "Google Graphics Array (GGA)" -and $_.status -eq "OK"} | disable-pnpdevice -confirm:$false | out-null
    get-pnpdevice | where-object {$_.friendlyname -like "Microsoft Hyper-V Video" -and $_.status -eq "OK"} | disable-pnpdevice -confirm:$false | out-null
    }

#Cleanup
function clean-up {
    progresswriter -status "Deleting temporary files from c:\parsectemp" -percentcomplete $percentcomplete
    remove-item -path c:\parsectemp\drivers -force -recurse
    remove-item -path c:\parsectemp -force -recurse
}

# --- MISSING EXECUTION BLOCK TO ADD BELOW ---

$scripttasklist = @(
"setup-environment";
"download-resources";
"set-time";
"enhance-pointer-precision";
"enable-mouse-keys";
"remove-shutdown";
"install-graphics-driver";
"install-parsec";
"clean-up"
)

try{
    foreach ($func in $scripttasklist) {
        $percentcomplete =$($scripttasklist.indexof($func) / $scripttasklist.count * 100)
        & $func $percentcomplete
    }
    # Restart to apply the NVIDIA Grid Driver
    restart-computer -force
}
catch{
    logger -event $_
}
