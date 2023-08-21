## Attacktive Directory

---

Tags: Windows, Active Directory, ASREProasting

Tools: NMAP, enum4linux, kerbrute, impacket, smbclient, evil-winrm

Process:

* Even though this room looks to be guided to some degree, I'm starting with my usual process. This means that I'm beginning with an nmap scan.

* As expected there is evidence of AD and some information.

* Next I run an enum4linux on the ip.

* `Kerbrute` is a tool for bruteforcing and enumerating users in kerberos and next I use that to try to further enumerate users.

* I needed to add the `<target ip>     spookysec.local` to /etc/hosts

* Now I can use impacket's `GetNPUsers` to ASREProast the users I've found

* I used John the Ripper to crack the ASREProasted account

* Using smbclient I listed the shares and then accessed them. One share had some encoded creds and I decoded them with cyberchef.

* Next I used Impacket's secretsDump `<path>/secretsdump.py <domain>/<user>:<pass>@<domain>` to dump more credentials where user:pass are taken from the backup creds

* Using evil-winrm and the NTLM hash for Administrator user, I logged in to the target.

* Grab the flags!