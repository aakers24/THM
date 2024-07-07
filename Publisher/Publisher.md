## Publisher

---

Tags: Linux, AppArmor, SPIP

Tools: nmap, ssh

Process:

* I started with my usual scans using nmap which showed SSH & Web servers, and then gobuster/dirb which didn't show much.

* There are many references to SPIP on the website. Googling shows that this is some sort of publishing system for internet content. There are also RCE CVEs for SPIP.

* I reran a gobuster dir scan with a different list (seclist web disovery 2.3 medium) and got a hit for /spip, which I also could have just tried based on the contents of the page.

* In the source code for the /spip page there is a tag that shows the version of SPIP which happens to match an RCE CVE.

* I ran the CVE but had problems because of quotes in the payload command. Because of this, I had to encode the payload into base64 and then in the payload command did `<base64 encoded command>|base64 -d|bash`. After this my listener got the connection from the target.

* User flag!

* In this user's home directory, there is also an .ssh folder with an SSH key inside that I can access.

* I cat out the contents of the id_rsa key and paste it into a key file on my machine. Then SSH into the target with this key (remembering to change its perms to 600 first...) and get a proper user shell.

* Going through my common PrivEsc vectors, there is an SUID binary called run_container. It appears to have to do with Docker and running strings on it (or just catting it like I did initially which was... gross) you can see it's running a script in `/opt/`.

* Trying to run it, some permissions are denied. This points to the presence of AppArmor which can protect certain functions/capabiltiies. 

* Looking at `echo $SHELL` or /etc/passwd it is apparent that the shell is set to /usr/sbin/ash. My understanding of this is that it is an executable that is run as the shell and AppArmor has a profile for it that dictates what its restrictions/permissions/capabilities are. The profile is visible at `/etc/apparmor.d/<profile>`.

* There are a couple of ways to bypass AA, but I just copied the shell binary to `/dev/shm/` which is shared memory location in Linux. Since AA is path based, the binary running from here evades AA.

* Since AA is bypassed, run_container.sh is now writable and code can be injected to gain a root shell.

* Now by adding the lines `chmod +s /bin/bash` and `/bin/bash -p` (Basically setting the SUID bit and then running it with inherited permissions) to the /opt/run_container.sh file, a root shell will be spawned when running /usr/sbin/run_container.

* Root shell and flag!