## 12/20/2022

## Nessus Lab Cont.

Figured out an initial foot hold. One of the targets had HeartBleed exploit. I tried this exploit initially yesterday but did not realize that you had to set the verbose mode to TRUE to be able to see the memory leak. In the memory leak I found credentials for SSH. I must learn to how to thoroughly investigate potential exploits. This stops me from constantly bouncing back and fourth between potential attack vectors so I can more methodically move through my enumeration.
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
