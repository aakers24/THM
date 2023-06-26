## Quotient

---

Tags: Windows, RDP, services, unquoted binary path service

Tools: nmap, remmina, msfvenom, netcat/nc

Process:

* nmap scanned, which was probably unnecessary because the room says to RDP into the machine with creds

* Standard privesc and enumeration/info-gathering

    * `systeminfo`

    * enumerate users with `net user`

    * `whoami` - /priv, /groups, etc.

    * `schtasks`, `sc query`

* I started with browsing the file system and checking directories with `dir /a:h` to check for hidden files because the hint in the description of the box says something about punctuation

    * There is an executable called Service in "C:\Program Files\Development Files\Devservice Files"

        * I searched schtasks and sc query for this service as "dev" (cmd:`findstr` ps:`Select-String` windows equivalents of `grep`) - no luck

        * I needed to `sc query "Development Service"` which I believe I tried earlier without quotes.

        * `sc qc`ing this service shows an unquoted binary path

* I made an msfvenom reverse tcp shell payload and downloaded it to the Development Files directory as Devservice.exe, then opened a listener for the revshell

* Restarted the computer from the cmd with `shutdown /r`

* My listener is now a system level shell! *flag*

---

*This section is just for my curiousity and understanding*

I'm trying to understand why doing this gives us a system level shell and not a shell as sage.

I assumed that the files I was uploading were owned by sage, which is obviously correct and confirmed with the command `dir /q` which shows the owners of the folders/files in the directory. One thought is maybe that the rev shell payload is just magic, but that really doesn't make sense to me.

I was trying to figure out if there was a command that showed who the service runs as to see if the service runs as system and that's why the shell is a system shell. Then I read through a writeup for the room that made a good point. When I had tried to sc stop/start the service I was denied access, which implies it is running as a higher privileged user. This might be the answer I was looking for. However, this doesn't seem satisfactory. I feel like there should be a command that shows what I'm looking for.

`sc sdshow <service>` gives the SDDL which can be converted with ps command `ConvertFrom-SddlString -sddl "<the given sddl from previous cmd>"`

I believe this is technically the answer I was looking for. It may be rough to read but it's readable and the info is all there.

---