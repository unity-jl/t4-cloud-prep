function InstallParsec {
    $userData = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text"
    $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($userData)) | convertfrom-json
    $arglist = "/silent /shared /vdd"
    $userAssigned = $false
    foreach($setting in $decoded.data){
        if($setting.value){
            if($setting.setting -eq "user_email"){
                $userAssigned = $true
            }
            elseif($setting.setting -eq "team_group_id" -and $userAssigned -eq $true){
                continue
            }
            $arglist += (" /{0}={1}" -f $setting.setting, $setting.value)
        }
    }     
    Start-Process "C:\ParsecTemp\Apps\parsec-windows.exe" -ArgumentList $arglist -wait
}

#Apps that require human intervention
function Install-Gaming-Apps {
    ProgressWriter -Status "Installing Parsec" -PercentComplete $PercentComplete
    InstallParsec
    Start-Process -FilePath "C:\Program Files\Parsec\parsecd.exe"
    Start-Sleep -s 1
    }

#Disable Devices
function disable-devices {
    ProgressWriter -Status "Disabling Microsoft Basic Display Adapter, Generic Non PNP Monitor and other devices" -PercentComplete $PercentComplete
    Get-PnpDevice | where {$_.friendlyname -like "Generic Non-PNP Monitor" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false | Out-Null
    Get-PnpDevice | where {$_.friendlyname -like "Microsoft Basic Display Adapter" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false | Out-Null
    Get-PnpDevice | where {$_.friendlyname -like "Google Graphics Array (GGA)" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false | Out-Null
    Get-PnpDevice | where {$_.friendlyname -like "Microsoft Hyper-V Video" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false | Out-Null
    }

#Cleanup
function clean-up {
    ProgressWriter -Status "Deleting temporary files from C:\ParsecTemp" -PercentComplete $PercentComplete
    Remove-Item -Path C:\ParsecTemp\Drivers -force -Recurse
    Remove-Item -Path $path\ParsecTemp -force -Recurse
    }

#cleanup recent files
function clean-up-recent {
    ProgressWriter -Status "Delete recently accessed files list from Windows Explorer" -PercentComplete $PercentComplete
    remove-item "$env:AppData\Microsoft\Windows\Recent\*" -Recurse -Force | Out-Null
    }

InstallParsec
Install-Gaming-Apps
disable-devices
clean-up
clean-up-recent
restart-computer -force