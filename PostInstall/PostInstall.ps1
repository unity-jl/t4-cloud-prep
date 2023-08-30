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
    (New-Object System.Net.WebClient).DownloadFile("https://builds.parsecgaming.com/package/parsec-windows.exe", "C:\ParsecTemp\Apps\parsec-windows.exe")

    #FIX THIS. PARSE PAGE LINKS INSTEAD.

    (new-object System.Net.WebClient).downloadfile("https://download.microsoft.com/download/2/5/a/25ad21ca-ed89-41b4-935f-73023ef6c5af/528.89_grid_win10_win11_server2019_server2022_dch_64bit_international_Azure_swl.exe", "c:\parsectemp\drivers\GRID_driver.exe")
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
    $url = invoke-webrequest -uri https://www.7-zip.org/download.html -usebasicparsing
    (new-Object system.net.webclient).downloadfile("https://www.7-zip.org/$($($url.links | where-object outerhtml -match "Download")[1].href)","c:\parsectemp\apps\7zip.exe")
    start-process c:\parsectemp\apps\7zip.exe -argumentList '/S /D="c:\program files\7-zip"' -wait
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
    $userdata = invoke-restmethod -headers @{"Metadata"="true"} -method GET -uri "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text"
    $decoded = [system.text.encoding]::utf8.getstring([convert]::frombase64string($userdata)) | convertfrom-json
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
    remove-item -path c:\cloud_prep -force -recurse
 }

$scripttasklist = @(
"setup-environment";
"download-resources";
"set-time";
"enhance-pointer-precision";
"enable-mouse-keys";
"remove-shutdown";
"install-graphics-driver";
"install-parsec";
"disable-devices";
"clean-up"
)

try{
    foreach ($func in $scripttasklist) {
        $percentcomplete =$($scripttasklist.indexof($func) / $scripttasklist.count * 100)
        & $func $percentcomplete
        }
    restart-computer -force
}
catch{
    logger -event $_
}