## Attacktive Directory

---

Tags: Windows, Active Directory

Tools: NMAP, enum4linux, kerbrute

Process:

* Even though this room looks to be guided to some degree, I'm starting with my usual process. This means that I'm beginning with an nmap scan.

* As expected there is evidence of AD and some information.

* Next I run an enum4linux on the ip.

* `Kerbrute` is a tool for bruteforcing and enumerating users in kerberos and next I use that to try to further enumerate users.

* I needed to add the `<target ip>     spookysec.local` to /etc/hosts

* Now I can ASREProast the users I've found

* I used John the Ripper to crack the ASREProasted account

* Using smbclient I listed the shares and then accessed them. One share had some encoded creds and I decoded them with cyberchef.

* 