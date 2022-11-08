## 11/2/2022
# OSCP-Prep
Notes on various topics while I prepare for the OSCP exam

Note that these notes are not meant to be used to teach a class or do a presentation, and thus are not fully expanded. These are notes of things that I think may be useful to review in the future. Also I have already finished INE's System, and Information Gathering / Enumeration Sections, so there won't be notes here


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
**- INE didn't mention this, but searches returned that this is one way to take over a domain. AD Domain Takeovers are part of the new OSCP. Keep an eye on this**
