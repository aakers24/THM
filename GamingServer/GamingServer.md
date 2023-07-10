## GamingServer

---

Tags: Linux, Web Exploitation, ssh

Tools: nmap, dirb, chmod, john / johntheripper / john2ssh, ssh

Process:

* As usual I start with an nmap scan of the given IP `nmap -A <IP> > scan`

* There are ssh and web servers

* So I start a `dirb` scan on the web server

    * The scan shows a robots.txt, /secrets/, /uploads/

* While the dirb scan runs, I investigate the website myself

    * Most of the links are dummy links, but there are 2 that work

    * The source of the main page reveals a comment giving us a possible username: *john*

* One of the links on the main page leads to a page which has an uploads button that takes you to an /uploads/ dir

    * This has 3 entries. 1 is a dictionary which looks like a password list or something similar. 2 is a hacker manifesto. 3 is a meme picture.

    * These make me think I'm not the first one to try to hack this site. Are these evidence of a previous hacker?

* I downloaded the dict and the meme

    * I couldnt find anything with `exiftool`, `steghide`, `binwalk` in the meme

* I started a `hydra` attack on the ssh server with john and the dict

    * no luck

* I looked in the /secret/ dir and there was a private RSA key!

    * I copied this into a file and used `chmod 600 <key file>` so it could be used with ssh, then `john2ssh <file> <file2>`
    
    * Then I used `john --wordlist=<rockyou.txt> <file2>` and got a password!

* I got into the box with `ssh john@<IP> -i <key file>`

* `id` shows many interesting and possibly exploitable groups

* *I got stuck because there were few privesc vectors i could find and most of them required knowing the user's password which I didn't because I got in with a key*

* The group that had a valid privesc vector was lxd and I found a reference at "steflan-security.com"

    * Start with the cloning on your own machine and once you generate the .tar.gz files you make a server and wget them onto the target machine and continue the process from there!

* Rooted!

* From here cd into /mnt/root and go nuts!