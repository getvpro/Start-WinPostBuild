<#

Runs various post install script on windows based assets (Win 10 / Win 201x server)

Oct 14, 2017
- Disabled WINS/NetBios disabled, sets DNS suffix	
- Changes CDROM drive to R
- IntallsInstall remote mgmt tools
- Corrected logic for MSC installs as follows IF ((Get-WindowsFeature XXYY).Installed -eq $False)

Jan 5, 2018
 - Added "select -first 1" on DVD rom change to resolve issue with multi DVD VM's

 Jan 8, 2017
 - Added copy-item $Dir\ChocApps.ps1 c:\Scripts -force

 March 2, 2018
 - Get/Add windows features now only runs on Windows server OS, same for disabling server manager from start-up. $SrcScripts var added

 March 3, 2018
 - Chocolatey install added

April 12, 2018
- Win Updates scripts is now copied down

June 13, 2018
 - Hyper-V RSAT added

 June 17, 2018
 - Removed .lnk creation

July 23, 2018
- Updated to set power plan to high perf

Aug 5, 2018
- Updated to include file copy of default powershell profile.ps1

Aug 8, 2018
- Amended means by which powerplan is set, as the method doesn't work on some builds on win 10
- Added code to remove pined start menu items for Edge/Store/Mail
- Added code to remove Microsoft Edge.lnk where it's found	

Aug 20, 2018
- Added code to set C drive name to $Env:Computername

Sept 7, 2018
- Added code for silent vmware tools install - where required
- Removed code to copy down MapAll.ps1
- Amended type-o on DHCP RSAT
- Amended type-o on Hyper-V tools install

Sept 23, 2018
- Removed VMWARE install code, as it's covered by PostBuild-MDT
- Removed code to purge MS apps: Edge, Mail, Store etc, moved to new script which will be in Win 10 MDT builds: Remove-W10-MSApps.ps1

March 20, 2019
- VMWARE Tools silent install added for non-MDT builds

April 17, 2019
- Added RSAT install for Win 10 builds

July 2, 2020
- Removed copy of older windows update scripts/folder

July 10, 2020
- Added BGInfo custom copy

July 14, 2020
- Added "Patch My PC"

July 15, 2020
- Added sys internals

July 19, 2020
- Updated BGINFO copies
- Code hygiene
- Now using Settings.xml
- Removed references to older MapAll.lnk

July 20, 2020
- DVD Drive letter now read from settings.xml
- VMwaretools install path variable is now read from settings.xml
- Microsoft Sys internals tools path now read as a variable from settings.xml
- Install detection logic added to Win 10 "add-windowscapability" section

#> 

$RunningPath = Split-Path $MyInvocation.MyCommand.Path -Parent

$XMLSet = ""
[XML]$XMLSet = Get-Content ($RunningPath + "\Settings.xml")

IF (-not($XMLSet)) {

    write-warning -Message "XML settings file not found under $RunningPath, script will now exit"    
    EXIT
}

$SrcScripts = $XMLSet.Properties.Global.SrcScripts
$DVDLetter = $XMLSet.Properties.Global.DVDLetter + "`:"
$ChocoChoice = $XMLSet.Properties.Global.Choco
$VMWARETools = $XMLSet.Properties.Global.VMWARETools
$MSSYSTools = $XMLSet.Properties.Global.MSSYSTools

write-host "Settings XML has been parsed"
write-host "$SrcScripts"
Write-host $DVDLetter
Write-host $ChocoChoice
Write-host $VMWARETools

Write-host "Change optical drive to the letter R" -ForegroundColor cyan
$DVD = Get-CimInstance -Class Win32_Volume -Filter "DriveType=5" | Select-Object -first 1

IF ($DVD) {
    
    Set-CimInstance -InputObject $Dvd -Arguments @{DriveLetter=$DVDLetter}

}

function Get-VMToolsInstalled {    
    
    $x86 = ((Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall") |
        Where-Object { $_.GetValue( "DisplayName" ) -like "*VMware Tools*" } ).Length -gt 0;

    $x64 = ((Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") |
        Where-Object { $_.GetValue( "DisplayName" ) -like "*VMware Tools*" } ).Length -gt 0;

    return $x86 -or $x64;
}

write-host "Disabling NetBIOS on all adapters" -ForegroundColor cyan
$adapters=(Get-WmiObject win32_networkadapterconfiguration )
Foreach ($adapter in $adapters){
  Write-Host $adapter
  $adapter.settcpipnetbios(2)
}

IF ((Get-WMIObject -class win32_operatingsystem).Caption -like "*Server*") {

    Write-host "Add reg key to stop server manager from starting on logon" -ForegroundColor Cyan
    New-ItemProperty -Path HKCU:\Software\Microsoft\ServerManager -Name DoNotOpenServerManagerAtLogon -PropertyType DWORD -Value "0x1" –Force

}

### Update / create script files under c:\Scripts
write-host "Copying logon script to c:\Scripts" -foregroundcolor cyan
IF (!(test-path c:\Scripts)) {new-item c:\Scripts -Type Directory}
copy-item $SrcScripts\Run-PostBuild\StaticNIC.ps1 c:\Scripts -force

### install chocolatey

IF ((!(test-path C:\ProgramData\chocolatey\choco.exe)) -and ($ChocoChoice -eq "Y")) {    

	write-warning "Chocolatey is not installed on this machine. Proceeding to install via web install method"
    Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    copy-item $SrcScripts\Distribution\ChocApps.ps1 c:\Scripts -force
}


### Windows server - Adding RSAT roles

IF ((Get-WMIObject -class win32_operatingsystem).Caption -like "*Server*") {

    write-host "Windows server OS confirmed, proceeding with windows feature changes" -ForegroundColor cyan

    IF ((Get-WindowsFeature RSAT-DHCP).Installed -eq $False) {

        write-host "Installing DHCP remote admin role" -ForegroundColor cyan
        Install-WindowsFeature RSAT-DHCP
    }

    IF ((Get-WindowsFeature RSAT-DNS-Server).Installed -eq $False) {

        write-host "Installing DNS remote admin feature"
        Install-WindowsFeature RSAT-DNS-Server
    }

    IF ((Get-WindowsFeature RSAT-AD-Tools).Installed -eq $False) {

        write-host "Installing AD remote admin feature"
        Install-WindowsFeature RSAT-AD-Tools
    }

    IF ((Get-WindowsFeature GPMC).Installed -eq $False) {

        write-host "Installing GPMC remote admin feature"
        Install-WindowsFeature GPMC
    }

    IF ((Get-WindowsFeature RSAT-Hyper-V-Tools-).Installed -eq $False) {

        write-host "Installing Hyper-V-Tools remote admin feature"
        Install-WindowsFeature Hyper-V-Tools
    }


}

### install RSAT roles on Win 10

IF ((Get-WmiObject -class win32_operatingsystem).Caption -like "*Windows 10*") {

    $Roles = @(
    "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
    "Rsat.DHCP.Tools~~~~0.0.1.0"
    "Rsat.Dns.Tools~~~~0.0.1.0"
    "Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0"
    "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"
    "Rsat.ServerManager.Tools~~~~0.0.1.0"
    )

    ForEach ($Item in $Roles) {

        IF ((Get-WindowsCapability -online -Name $Item).State -ne "Installed") {

            write-host "Adding windows capability $Item"            
            Add-WindowsCapability -Online -name $Item
        
        }
    }

}

### Set High-perf powerprofile if not laptop type

If (!(Get-WmiObject -Class win32_battery)) {

    write-host "Asset is not a laptop, setting power profile to high performance"
    write-host "`r`n"
    powercfg.exe -SETACTIVE "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
}

IF (test-path "$SrcScripts\Powershell profiles\profile.ps1") {    
    
    write-host "Copying over windows powershell profile to local system"
    write-host "`r`n"

    copy-item -Path "$SrcScripts\Powershell profiles\profile.ps1" -Destination "$Env:SystemRoot\System32\WindowsPowerShell\v1.0\" -force

 }

### Change C drive name to match $Env:Computername
IF ($Drive.Label -ne $env:COMPUTERNAME) {

    write-host "Change C drive name to match $Env:Computername" -ForegroundColor Cyan
    write-host "`r`n"

    $drive = Get-WMIObject win32_volume -Filter "DriveLetter = 'C:'"
    $drive.Label = $env:COMPUTERNAME
    $drive.put()

}

Else {Write-host "Not required"}

### VMware Tools silent install

If ((Get-WMIObject -class Win32_computersystem).Model -like "VMWARE*") {

Get-VMToolsInstalled

    IF ((Get-VMToolsInstalled) -eq $False) {

        write-host "Starting VMWARE Tools silent install"
        write-host "`r`n"

        start-process -FilePath $VMWARETools -argumentlist @('/s /v /qn reboot=r') -wait

    }

    Else {

        write-host "VMWARE Tools is installed already"

    }

}


IF (-not(test-path "c:\installs")) {

    new-item "c:\Installs" -ItemType Directory -Force

}

### BGInfo

IF (-not(test-path "c:\installs\BGInfo")) {

    write-host "Creating BGINFO folder" -ForegroundColor Cyan
    write-host "`r`n"
    new-item "c:\Installs\BGinfo" -ItemType Directory -Force

}

write-host "Copying over BG Info files" -ForegroundColor Cyan
write-host "`r`n"

Copy-item "$MSSYSTools\BGinfo\Bginfo64.exe" -Destination "c:\Installs\BGinfo" -Force
Copy-item "$MSSYSTools\BGinfo\Files\Server.bgi" -Destination "c:\Installs\BGinfo" -Force
Copy-item "$MSSYSTools\BGinfo\Files\*.bmp" -Destination "c:\Installs\BGinfo" -Force
Copy-item "$MSSYSTools\BGinfo\Files\Apply.bat" -Destination "C:\Installs\BGinfo" -Force

### Patch My PC
    
IF (-not(test-path "c:\installs\PatchMyPC.exe")) {

    Copy-item "$MSSYSTools\PatchMyPC\PatchMyPC.exe" -Destination "c:\Installs" -Force
}

### Sys Internals
### https://docs.microsoft.com/en-us/sysinternals/downloads/

IF (-not(test-path "$Env:SystemRoot\System32\autoruns.exe")) {

    Write-host "Copying over Microsoft system internal system tools to $Env:SystemRoot\System32"
    write-host "`r`n"

    copy-item "$MSSYSTools\SysinternalsSuite\Autoruns.exe" "$Env:SystemRoot\System32" -Force
    copy-item "$MSSYSTools\SysinternalsSuite\Autoruns64.exe" "$Env:SystemRoot\System32" -Force

    copy-item "$MSSYSTools\SysinternalsSuite\procexp.exe" "$Env:SystemRoot\System32" -Force
    copy-item "$MSSYSTools\SysinternalsSuite\procexp64.exe" "$Env:SystemRoot\System32" -Force
    
    copy-item "$MSSYSTools\SysinternalsSuite\procmon.exe" "$Env:SystemRoot\System32" -Force
    copy-item "$MSSYSTools\SysinternalsSuite\procmon64.exe" "$Env:SystemRoot\System32" -Force
    
    copy-item "$MSSYSTools\SysinternalsSuite\psexec.exe" "$Env:SystemRoot\System32" -Force
    copy-item "$MSSYSTools\SysinternalsSuite\psexec64.exe" "$Env:SystemRoot\System32" -Force

    copy-item "$MSSYSTools\SysinternalsSuite\tcpview.exe" "$Env:SystemRoot\System32" -Force

    copy-item "$MSSYSTools\SysinternalsSuite\CPUstres.exe" "$Env:SystemRoot\System32" -Force
    copy-item "$MSSYSTools\SysinternalsSuite\CPUstres64.exe" "$Env:SystemRoot\System32" -Force
    
    copy-item "$MSSYSTools\Delprof\DelProf2.exe" "$Env:SystemRoot\System32" -Force

}