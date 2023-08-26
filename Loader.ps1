Write-Host -foregroundcolor red "
                               ((//////                                
                             #######//////                             
                             ##########(/////.                         
                             #############(/////,                      
                             #################/////*                   
                             #######/############////.                 
                             #######/// ##########////                 
                             #######///    /#######///                 
                             #######///     #######///                 
                             #######///     #######///                 
                             #######////    #######///                 
                             ########////// #######///                 
                             ###########////#######///                 
                               ####################///                 
                                   ################///                 
                                     *#############///                 
                                         ##########///                 
                                            ######(*                   
                                                           
                           
                                       
                    Parsec NC4as_T4_v3 Setup Script

                    This script installs Nvidia T4 GRID 
                    driver, parses virtual machine user 
                    data, installs Parsec and provisions 
                    Team computer.
                    
                    It's provided with no warranty, 
                    so use it at your own risk.

                    This tool supports:

                    OS:
                    Windows 10
                    
                    CLOUD SKU:
                    Azure NC4as_T4_v3   (Tesla T4)
    
"                                         
Write-Output "Setting up Environment"
$path = "c:\"
if(!(Test-Path -Path $path\ParsecTemp)){
    New-Item -Path $path\ParsecTemp -ItemType directory| Out-Null
}

Unblock-File -Path "c:\cloud_prep\t4-cloud-prep-main\*"
#Unblocking all script files
Write-Output "Unblocking files just in case"
Get-ChildItem -Path $path\ParsecTemp -Recurse | Unblock-File
Write-Output "Starting main script"
start-process powershell.exe -verb RunAS -argument ("-file " + $path + "cloud_prep\t4-cloud-prep-main\PostInstall\PostInstall.ps1") 