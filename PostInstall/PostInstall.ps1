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
function setupEnvironment{
    progressWriter -status "Moving files and folders into place" -percentcomplete $percentcomplete
    #New-Item -Path $env:ProgramData\ParsecLoader -ItemType directory | Out-Null
    #Move-Item -Path $path\ParsecTemp\PreInstall\TeamMachineSetup.ps1 -Destination $env:ProgramData\ParsecLoader}
    new-item -path c:\parsectemp\apps -itemtype directory | out-null
    new-item -path c:\parsectemp\drivers -itemtype directory | out-null
}

#download-T4-GRID-driver
function download-resources{
    progresswriter -status "Downloading GRID Driver" -percentcomplete $percentcomplete

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
function enable-mousekeys {
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
    start-process c:\parsectemp\apps\7zip.exe -argumentList '/s /d="c:\program files\7-zip"' -wait
}

#install-graphics-driver
function install-graphics-driver {
    progresswriter -status "Installing 7Zip and GPU Driver" -percentcomplete $percentComplete
    install7zip
    cmd.exe /c '"c:\program files\7-zip\7z.exe" x c:\parsectemp\drivers\grid_driver.exe -oC:\parsectemp\drivers\grid_driver -y' | Out-Null
    cmd.exe /c "c:\parsectemp\drivers\grid_driver\setup.exe /s"
}

<#
#Sets all applications to force close on shutdown
function force-close-apps {
    ProgressWriter -Status "Setting Windows not to stop shutdown if there are unsaved apps" -PercentComplete $PercentComplete
    if (((Get-Item -Path "HKCU:\Control Panel\Desktop").GetValue("AutoEndTasks") -ne $null) -eq $true) {
        Set-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value "1"
        }
    Else {
        New-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value "1"
        }
    }

#disable logout start menu
function disable-logout {
    ProgressWriter -Status "Disabling log out button on start menu" -PercentComplete $PercentComplete
    if((Test-RegistryValue -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Value StartMenuLogOff )-eq $true) {Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null} Else {New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null}
    }

#disable lock start menu
function disable-lock {
    ProgressWriter -Status "Disabling option to lock your Windows user profile" -PercentComplete $PercentComplete
    if((Test-Path -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System) -eq $true) {} Else {New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies -Name Software | Out-Null}
    if((Test-RegistryValue -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Value DisableLockWorkstation) -eq $true) {Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null } Else {New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null}
    }

#set update policy
function set-update-policy {
    ProgressWriter -Status "Disabling Windows Update" -PercentComplete $PercentComplete
    if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'DoNotConnectToWindowsUpdateInternetLocations') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null}
    if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'UpdateServiceURLAlternative') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null}
    if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'WUServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null}
    if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'WUSatusServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null}
    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "AUOptions" -Value 1 | Out-Null
    if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -value 'UseWUServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null} else {new-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null}
}

 #Audio Driver Install
function AudioInstall {
    (New-Object System.Net.WebClient).DownloadFile("https://download.vb-audio.com/Download_CABLE/VBCABLE_Driver_Pack43.zip", "C:\ParsecTemp\Apps\VBCable.zip")
    New-Item -Path "C:\ParsecTemp\Apps\VBCable" -ItemType Directory| Out-Null
    Expand-Archive -Path "C:\ParsecTemp\Apps\VBCable.zip" -DestinationPath "C:\ParsecTemp\Apps\VBCable"
    $pathToCatFile = "C:\ParsecTemp\Apps\VBCable\vbaudio_cable64_win7.cat"
    $FullCertificateExportPath = "C:\ParsecTemp\Apps\VBCable\VBCert.cer"
    $VB = @{}
    $VB.DriverFile = $pathToCatFile;
    $VB.CertName = $FullCertificateExportPath;
    $VB.ExportType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert;
    $VB.Cert = (Get-AuthenticodeSignature -filepath $VB.DriverFile).SignerCertificate;
    [System.IO.File]::WriteAllBytes($VB.CertName, $VB.Cert.Export($VB.ExportType))
    Import-Certificate -CertStoreLocation Cert:\LocalMachine\TrustedPublisher -FilePath $VB.CertName | Out-Null
    Start-Process -FilePath "C:\ParsecTemp\Apps\VBCable\VBCABLE_Setup_x64.exe" -ArgumentList '-i','-h'
    Set-Service -Name audiosrv -StartupType Automatic
    Start-Service -Name audiosrv
    }
#>

<#
function register-parsec-provisioning-task{
    start-process powershell -verb runas -argumentlist @'
    $action = new-scheduledtaskaction -execute 'c:\windows\system32\windowspowershell\v1.0\powershell.exe' -argument '-file c:\cloud_prep\t4-cloud-prep-main\preinstall\teammachinesetup.ps1'
    $trigger =  new-scheduledtasktrigger -atstartup
    $principal = new-scheduledtaskprincipal -userid "SYSTEM" -logontype serviceaccount -runlevel highest
    $settings = new-scheduledtasksettingsset -executiontimelimit (new-timespan -hours 1)
    register-scheduledtask -taskname provision_team_machine -action $action -trigger $trigger -principal $principal -settings $settings
'@ 
}
#>

<#
function installparsec{
    $userdata = invoke-restmethod -headers @{"metadata"="true"} -method get -uri "http://169.254.169.254/metadata/instance/compute/userdata?api-version=2021-01-01&format=text"
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
}
#>

#Apps that require human intervention
function install-parsec{
    progresswriter -status "Installing parsec" -percentcomplete $percentcomplete
    $userdata = invoke-restmethod -headers @{"metadata"="true"} -method get -uri "http://169.254.169.254/metadata/instance/compute/userdata?api-version=2021-01-01&format=text"
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
    remove-item -path $path\parsectemp -force -recurse
 }

$scripttasklist = @(
"setupenvironment";
"create-directories";
"download-resources";
"set-time";
"enhance-pointer-precision";
"enable-mouse-keys";
"remove-shutdown";
"install-graphics-driver";
"install-parsec"
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