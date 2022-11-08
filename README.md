# OSCP-Prep
Notes on various topics while I prepare for the OSCP exam

Note that these notes are not meant to be used to teach a class or do a presentation, and thus are not fully expanded. These are notes of things that I think may be useful to review in the future


#Arp

Windows 10 show arp cache 
arp -a

TTL for ARP on switches is several minutes while on Windows its in the seconds
https://learn.microsoft.com/en-US/troubleshoot/windows-server/networking/address-resolution-protocol-arp-caching-behavior

In Windows...
netsh interface ipv4 show interfaces -- find ID for given interface

netsh interface ipv4 show interface <idx> find all info, such as TTL (Called Reachable Time, once it expires, ARP entry becomes "Stale" and host must make another request

Arp Requests can be broadcast on 00:00:00:00:00:00, FF:FF:FF:FF:FF:FF (Data Link) or 255.255.255.255 (IP)

There are other protocols in Arp family, such as RARP, INARP, etc... Inarp looked particularly interesting for further research

Apparently you can change ARP TTL using Registry Value
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
