## Windows

[[Unquoted Service Path]](https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae) 

`wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """ `

Unquoted Service Path: See if user has permissions to launch found executable...

`sc stop SERVICE`

`sc start SERVICE`



[[Bypass Uac]](https://github.com/hfiref0x/UACME)
[[UACME Hackersploit video]](https://www.youtube.com/watch?v=RXX0FHM9SEk)

# All
Generate Payloads

https://www.revshells.com/

## Meterpreter

create shell and check gcc version

`execute -f /bin/sh -i -c`

`gcc --version`
