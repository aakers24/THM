## Fowsniff

---

Tags: Linux, Web server, IMAP, pop3, OSINT

Tools: nmap, dirb, msfconsole, exploit-db, twitter/x

*By the way, pop3 is Post Office Protocol and IMAP is Internet Message Access Protocol. Also SMTP is Simple Mail Transfer Protocol.* <br/>
*I've seen these forever, but hopefully noting these helps me remember.*

Process:

* As usual start with nmap -A scan

* Ports 22, 80, 110, and 143 were open. 110 and 143 seem to have something to with Dovecot/IMAP

* I started by investigating the website.

    * The links are dummy links and there isn't much to go off in the source except some directories which didnt seem to lead anywhere. I started a subdirectory scan that never ended up giving me anything too useful.

* While that scan started, I began looking into the other open ports and what Dovecot/IMAP is as well as if they have any easy vulnerabilities to exploit. I looked on exploit-db and msfconsole, but the msfconsole didn't work (it was the wrong exploit) and the exploit-db script requires an account.

* I went back to the website to look for account names/emails or anything else to help find accounts or other vulnerabilities. It turns out I just didn't really read the website and there was useful info pointing to a twitter handle on the page.

    * I didn't want to create a twitter account just to log in and see it so I did peek at someone's walkthrough just to snag the info from the tweet. The info was apparently just a tweet to a pastebin that was a user/hash dump for the site/company.

* I cracked all of the md5 hashes with crackstation (except one that wouldn't identify as md5 on crackstation and wouldn't crack on another site)

* I tried plugging the corresponding user:pass combos into the ssh server with no luck.

* At this point I had lots of ideas including using the exploit-db script with the newly found accounts, bruteforcing the ssh with a userlist made from the accounts, and more, but to keep things simple I followed the hint I noticed on the thm room page which asked if I could bruteforce the pop3 login with metasploit using the new info.

* Using netcat with port 110 `nc <ip> 110` and the creds confirmed with the bruteforce I logged into the pop3 server.

* In one of the emails there is a "temp" password. Using this with the username of the sender of the other email (read both emails to see why) in ssh, access to the machine is established.

* Using `find / -group <gid>` an unusual/interesting/useful file can be found.

* Using `revshells.com` and putting the shell python3#2-/bin/sh in this file and relogging into the ssh gives access to a shell as different user on my listener. This is because there is a motd (message of the day) script running as root when a user logs in and it calls this cube.sh.

* Rooted! There is a flag, but it doesn't even ask for it in the room.