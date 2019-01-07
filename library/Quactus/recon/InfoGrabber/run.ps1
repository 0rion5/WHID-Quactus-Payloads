#Remove run history
powershell "Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -Name '*' -ErrorAction SilentlyContinue"

#Get the path and file name that you are using for output
# find mounted drive:
$VolumeName = "C:\"
$computerSystem = Get-CimInstance CIM_ComputerSystem
$backupDrive = $null
get-wmiobject win32_logicaldisk | % {
    if ($_.VolumeName -eq $VolumeName) {
        $backupDrive = $_.DeviceID
    }
}

#See if a quactus folder exist in C:\. If not create one
$TARGETDIR = $backupDrive + "\quactus"
if(!(Test-Path -Path $TARGETDIR )){
    New-Item -ItemType directory -Path $TARGETDIR
}

#See if a info folder exist in quactus folder. If not create one
$TARGETDIR = $backupDrive + "\quactus\info"
if(!(Test-Path -Path $TARGETDIR )){
    New-Item -ItemType directory -Path $TARGETDIR
}

#Create a path that will be used to make the file
$datetime = get-date -f yyyy-MM-dd_HH-mm
$backupPath = $backupDrive + "\quactus\info\" + $computerSystem.Name + " - " + $datetime + ".txt"

#Create output from info script
$TARGETDIR = $MyInvocation.MyCommand.Path
$TARGETDIR = $TARGETDIR -replace ".......$"
cd $TARGETDIR
PowerShell.exe -ExecutionPolicy Bypass -File info.ps1 > $backupPath