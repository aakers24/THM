## Tech_Supp0rt:1

---

Tags: Linux, samba, privesc

Tools: nmap, dirb, ssh, smbmap, smbclient, cyberchef, gtfobins

Process:

* As usual I started with an nmap scan of the given \<ip\>

    * There is a webserver on port 80 so I start with the usual directory scanning with `dirb`.

    * There is also smb running and it looks like a guest logon is allowed.

        * I used `smbmap -H <IP> -u anonymous` to find out there's a read only share called websvr and connected with `smbclient \\\\<ip>\\websvr -U anonymous`

        * There was a file with some goals, creds for something called subrion, and a spot for wordpress creds thats empty

* The dirb scan came back with a /test/ dir and a /wordpress/ dir

    * test seems to be a static page and deadend while /wordpress/wp-admin looked promising but no creds worked

* googling subrion yields some information especially on the github

    * This shows that there is a robots.txt which shows a /panel dir which corresponds to the note on the smb share

* subrion/panel exists, works, and we have the creds!

    * the creds didnt actually work, but there was a "magic"al hint in the note with the creds

* After some cheffin, I'm in to the subrion panel

* now I used exploit-db to see if this subrion version has an exploit and it does

* CVE 2018-19422 and entering the correct path/creds gives arbitrary file upload and RCE for a shell

    * This shell isn't the most stable, but navigating around with ls and cat the wp-config file contains some creds

    * These are db creds, but the pass works with a user from /etc/passwd

* `sudo -l` and `gtfobins` gives an escalation vector!

* We can use this to read the flag!