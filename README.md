## About
AutoIPBan is a PowerShell script designed to run on a Windows Server in the background to prevent unwanted RemoteAccess to a server. It monitors Event ID 4625 (failed logins) and 4624 (successful logins) and automatically ban the IP addresses that have repeated failed login attempts within a configurable time period. The default is 5 fails within 24 hours.  
  
The program has an import/export functionality if you need to move lists between multiple servers. IPs can be banned manually from the list or by inputting the address. IPs can be whitelisted as well and there is also a protected list of whitelisted IP addresses in the program that you can edit if you open the .ps1 file. By default 1.1.1.1 is the only protected address, search for that and edit the list in $TrustedIPs to add more "protected" addresses (cannot be removed from Whitelist, noted by a * next to the address). The program creates firewall rules and audits those rules automatically within a configurable amount of time. All settings can be changed under the Settings menu.

## Installaion
Put AutoIPBan.ps1 here:  
+ "C:\ProgramData\AutoIPBan\AutoIPBan.ps1"

## Launching
Open PowerShell as Administrator and launch AutoIPBan by typing:  
+ & "C:\ProgramData\AutoIPBan\AutoIPBan.ps1"
<img width="655" height="333" alt="image" src="https://github.com/user-attachments/assets/274f8db7-37c9-4735-bf49-f8b5f91d300c" />

## Main Screen
<img width="1286" height="843" alt="image" src="https://github.com/user-attachments/assets/531f6ab6-cb72-4c52-8ce4-9c66dd4e014c" />

## Settings
<img width="366" height="433" alt="image" src="https://github.com/user-attachments/assets/beea0f00-8c6b-4c96-9161-7a3c48ab22c1" />
