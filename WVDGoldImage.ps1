<# 
    Script created by John Jenner John.Jenner@microsoft.com
    Updated 12/3/2019

    Updates by Mark hooks mark.hooks@microsoft.com
    Updated 1/31/202

    Updated to support Azure Image Builder
#>

# Set this variable to your FSLogix profile directory
$FSLUNC = "\\DC1\fslogix$"

# The following steps are from: https://docs.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image
# https://docs.microsoft.com/en-us/azure/virtual-desktop/install-office-on-wvd-master-image

#Set-ExecutionPolicy -ExecutionPolicy Unrestricted
#Install-Module -Name PowerShellGet -Repository PSGallery -Force -ErrorAction Stop
#Install-Module -Name Az -AllowClobber

### Download Application Packages
New-Item -Path 'C:\temp' -ItemType Directory -Force | Out-Null
Invoke-WebRequest -Uri 'https://buildscripts.blob.core.windows.net/buildscripts/WVDGoldImageAIB.zip' -OutFile 'c:\temp\WVDGoldImageAIB.zip'
Expand-Archive -Path 'C:\temp\WVDGoldImageAIB.zip' -DestinationPath 'C:\temp'  -Force


Write-Host "This script will prepare your image for capture and eventual upload to Azure."
Write-Host "Disabling Automatic Updates..."
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 1 /f


# Enter the following commands into the registry editor to fix 5k resolution support

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MaxMonitors /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MaxXResolution /t REG_DWORD /d 5120 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MaxYResolution /t REG_DWORD /d 2880 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs" /v MaxMonitors /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs" /v MaxXResolution /t REG_DWORD /d 5120 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs" /v MaxYResolution /t REG_DWORD /d 2880 /f



# Enable timezone redirection

Write-Host "Enabling time zone redirection..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEnableTimeZoneRedirection /t REG_DWORD /d 1 /f


# Disable Storage Sense

Write-Host "Disabling Storage Sense..."
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy /v 01 /t REG_DWORD /d 0 /f



# Remove the WinHTTP proxy

netsh winhttp reset proxy



# Set Coordinated Universal Time (UTC) time for Windows and the startup type of the Windows Time (w32time) service to Automatically

Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation' -name "RealTimeIsUniversal" -Value 1 -Type DWord -force
Set-Service -Name w32time -StartupType Automatic



# Set the power profile to the High Performance

powercfg /setactive SCHEME_MIN



# Make sure that the environmental variables TEMP and TMP are set to their default values

Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -name "TEMP" -Value "%SystemRoot%\TEMP" -Type ExpandString -force
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -name "TMP" -Value "%SystemRoot%\TEMP" -Type ExpandString -force



# Set Windows services to defaults - This typically fails due to a permissions error, need to investigate why. May be due to differences in client vs Server os

Set-Service -Name dhcp -StartupType Automatic
Set-Service -Name IKEEXT -StartupType Automatic
Set-Service -Name iphlpsvc -StartupType Automatic
Set-Service -Name netlogon -StartupType Manual
Set-Service -Name netman -StartupType Manual
Set-Service -Name nsi -StartupType Automatic
Set-Service -Name termService -StartupType Manual
Set-Service -Name RemoteRegistry -StartupType Automatic
Set-Service -Name Winrm -startuptype Automatic



# Ensure RDP is enabled

Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0 -Type DWord -force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -name "fDenyTSConnections" -Value 0 -Type DWord -force



# Set RDP Port to 3389 - Unnecessary for WVD due to reverse connect, but helpful for backdoor administration with a jump box 

Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -name "PortNumber" -Value 3389 -Type DWord -force



# Listener is listening on every network interface

Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -name "LanAdapter" -Value 0 -Type DWord -force



# Configure NLA

Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1 -Type DWord -force
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "SecurityLayer" -Value 1 -Type DWord -force
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "fAllowSecProtocolNegotiation" -Value 1 -Type DWord -force



# Set keep-alive value

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -name "KeepAliveEnable" -Value 1  -Type DWord -force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -name "KeepAliveInterval" -Value 1  -Type DWord -force
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -name "KeepAliveTimeout" -Value 1 -Type DWord -force



# Reconnect

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -name "fDisableAutoReconnect" -Value 0 -Type DWord -force
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -name "fInheritReconnectSame" -Value 1 -Type DWord -force
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -name "fReconnectSame" -Value 0 -Type DWord -force



# Limit number of concurrent sessions

Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -name "MaxInstanceCount" -Value 4294967295 -Type DWord -force



# Remove any self signed certs

Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "SSLCertificateSHA1Hash" -force -ErrorAction SilentlyContinue



# Turn on Firewall

Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True



# Allow WinRM

#REG add "HKLM\SYSTEM\CurrentControlSet\services\WinRM" /v Start /t REG_DWORD /d 2 /f
#If ((Get-Service -Name WinRM).Status -ne "Running") {
#    net start WinRM
#}
#Enable-PSRemoting -force
#Set-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" -Enabled True



# Allow RDP

Set-NetFirewallRule -DisplayGroup "Remote Desktop" -Enabled True



# Enable File and Printer sharing for ping

Set-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)" -Enabled True



# Add Defender exclusion for FSLogix

# Add-MpPreference -ExclusionPath $FSLUNC



#Add FSLogix settings

New-Item -Path HKLM:\Software\FSLogix\ -Name Profiles -Force
New-Item -Path HKLM:\Software\FSLogix\Profiles\ -Name Apps -Force
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "Enabled" -Type "Dword" -Value "1"
New-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "VHDLocations" -Value $FSLUNC -PropertyType MultiString -Force
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "SizeInMBs" -Type "Dword" -Value "32768"
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "IsDynamic" -Type "Dword" -Value "1"
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "VolumeType" -Type String -Value "vhd"
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "LockedRetryCount" -Type "Dword" -Value "12"
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "LockedRetryInterval" -Type "Dword" -Value "5"
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "ProfileType" -Type "Dword" -Value "3"
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "ConcurrentUserSessions" -Type "Dword" -Value "1"
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "RoamSearch" -Type "Dword" -Value "2" 
New-ItemProperty -Path HKLM:\Software\FSLogix\Profiles\Apps -Name "RoamSearch" -Type "Dword" -Value "2"
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "FlipFlopProfileDirectoryName" -Type "Dword" -Value "1" 
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "SIDDirNamePattern" -Type String -Value "%username%%sid%"
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "SIDDirNameMatch" -Type String -Value "%username%%sid%"


#Install Applications
Write-Host "Install Microsoft Edge 77"
Start-Process msiexec.exe -Wait -ArgumentList '/I c:\temp\MicrosoftEdgeEnterpriseX64.msi /quiet'
Write-Host "Install Notepad++"
Start-Process c:\temp\npp.7.8.4.Installer.exe -Wait -ArgumentList '/S'
Write-Host "Install FSLogix Agent"
Start-Process "c:\temp\FSLogix\x64\Release\FSLogixAppsSetup.exe" -Wait -ArgumentList '/install /quiet'
Write-Host "Install Office"
Start-Process "c:\temp\Office\Setup.exe" -Wait -ArgumentList '/configure c:\temp\office\configuration.xml'
Write-Host "Install OneDrive"
Start-Process "c:\temp\OneDriveSetup.exe" -Wait -ArgumentList '/silent'


#Configure Office
reg load HKU\TempDefault C:\Users\Default\NTUSER.DAT
reg add "HKU\TempDefault\software\policies\microsoft\office\16.0\outlook\cached mode" /v enable /t REG_DWORD /d 1 /f
reg add "HKU\TempDefault\software\policies\microsoft\office\16.0\outlook\cached mode" /v syncwindowsetting /t REG_DWORD /d 1 /f
reg add "HKU\TempDefault\software\policies\microsoft\office\16.0\outlook\cached mode" /v CalendarSyncWindowSetting /t REG_DWORD /d 1 /f
reg add "HKU\TempDefault\software\policies\microsoft\office\16.0\outlook\cached mode" /v CalendarSyncWindowSettingMonths  /t REG_DWORD /d 1 /f
reg unload HKU\TempDefault
reg add HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate /v hideupdatenotifications /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate /v hideenabledisableupdates /t REG_DWORD /d 1 /f


#Configure OneDrive for Business
Write-Host "Setting OneDrive for Business policies" 
#Configure OneDrive to start at sign-in for all users
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDrive /t REG_SZ /d "C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe /background" /f
#Silently configure user accounts
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\OneDrive" /v "SilentAccountConfig" /t REG_DWORD /d 1 /f
#Redirect and move Windows known folders to OneDrive
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\OneDrive" /v "KFMSilentOptIn" /t REG_SZ /d "bad69d79-XXXX-XXXX-9157-966cbd2d9933" /f

Write-Host "AIB PowerShell Script Complete"
# Complete

# Launch Sysprep

Write-Host "We'll now launch Sysprep."
#C:\Windows\System32\Sysprep\Sysprep.exe /generalize /oobe /shutdown
C:\Windows\System32\Sysprep\Sysprep.exe