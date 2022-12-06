## 12/6/2022

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
