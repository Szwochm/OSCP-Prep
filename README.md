
# OSCP-Prep


# Progress

![INE eCPPT Progress](https://github.com/Szwochm/OSCP-Prep/blob/main/Progress%20INE.PNG?raw=true)

- [x] Penetration Testing: System Security (12 Hrs, 50 Mins)
- [ ] Penetration Testing: Network Security (33 Hrs, 14 Mins) **IN PROGRESS: 40% completed**
- [ ] PowerShell for Pentesters (6 Hrs, 29 Mins)
- [ ] Penetration Testing: Web App Security (9 Hrs, 44 Mins)
- [ ] Penetration Testing: Wi-Fi (5 Hrs, 14 Mins)
- [ ] Penetration Testing: Metasploit & Ruby (7 Hrs, 51 Mins)
- [ ] eCPPTv2 Exam Prep (1 Hr, 15 Mins)




# Intent
These are notes on various topics while I prepare for the OSCP exam

These notes are not meant to be used to teach a class or do a presentation, and thus are not fully expanded. These are notes of things that I think may be useful to review in the future. Also I have already finished INE's System, and Information Gathering / Enumeration Sections, so there won't be notes here (I used Notion for those)

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

## 11/11/2022

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

mkdir /tmp/finance

mount -t cifs -o user=almir,password=Corinthians2012,rw,vers=1.0 //172.16.5.10/finance /tmp/finance

ls -l /tmp/finance/











