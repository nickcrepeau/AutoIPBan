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

## Trusted IPs
Open C:\ProgramData\AutoIPBan\AutoIPBan.ps1 with Notepad++ or another similar application. Find this line: <b>$TrustedIPs = @(</b>  
Then add any IP addresses here that should be permanently whitelisted. Any that are added to TrustedIPs cannot be removed from the whitelist and will have a * next to them in the running program.

## Task Scheduler
I recommend having creating a task to automatically start AutoIPBan when your server launches. Open "Task Scheduler" on your Windows Server and click "Create Task..." and input the follow settings:
+ General - Name = AutoIPBan and click "Run with highest privileges"
+ Triggers - Click "New..." and select "At startup" in the drop-down menu, Enabled is checked by default click OK
+ Actions - Click "New..." and select "Start a program" in the drop-down menu, Program/Script = powershell.exe then Add arguments = -NoProfile -ExecutionPolicy Bypass -STA -File "C:\ProgramData\AutoIPBan\AutoIPBan.ps1" and Start in = C:\ProgramData\AutoIPBan
+ Conditions - All blank don't change
+ Settings - All of these should be checked: Allow task to be run on demand, Run task as soon as possible after a scheduled start is missed, If the task fails, restart every 1 minute up to 3 times, If the running task does not end when requested, force it to stop

Once the task is made you can start and stop the program easily from here by clicking "Run" and "End" in Task Scheduler
