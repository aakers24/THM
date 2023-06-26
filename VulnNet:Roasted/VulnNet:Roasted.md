## VulnNet: Roasted

---

Tags: Windows, Kerberoasting, AS-REP roasting, smb, kerberos, johntheripper, Active Directory, AD, roasting, enumeration, sid/rid

Tools: nmap, enum4linux, crackmapexec, smbclient, smbmap, evil-winrm, ftp, impacket tools suite

Process (Extra Verbose as I'm trying to level up my windows skills):

* nmap scan failed, retried with -Pn, then -A on ports that got hits

* enum4linux

    * domain name: vulnnet-rst

### *Note: I could have added the \<ip\> \<hostname\> to /etc/hosts on my vm, but didn't*

* smbmap as guest

    * smbclient as guest to read only shares, get txt files, these give username hints

* grab RIDs with guest user by brute force (crackmapexec smb \<host\> -u guest -p '' --rid-brute)

    * Make user file with list of names

* roast login tokens that dont require preauth (AS-REP roasting) (impacket/examples/GetNPUsers.py \<host\> -dc-ip \<target ip\> -no-pass -usersfile /<users file/>)

    * crack roasted tokens with johntheripper (hashcat is an alternative)

    * try to winrm with these creds - no luck

* Use newly cracked creds to re-roast (impacket/examples/GetUserSPNs.py \<host\>/user:pass -dc-ip \<target ip\> -request) (-outputfile optional)

    * crack these same as the previous creds

    * try to winrm with these creds - hit!

    * could still try reroasting with new creds

    * smbmapped again with new creds and found a password reset script with plaintext creds for a-whitehat

* Evil-winrm shell as enterprise-core-vn

    * User level access

    * grab flag from user desktop

    * Priv esc
        
        * Nothing useful in whoami /priv

        * Upload winpeas to C:\temp (mkdir temp first)

            * Had to upload bat version because windows detected the exe was a virus

            * Didn't notice anything particularly useful (might have missed something)

* Winrm shell as a-whitehat

    * "whoami /groups" reveals domain admin group membership

    * "whoami /priv" reveals a lot of privs, including some with privesc vectors

        * Following the SeTakeOwnership vector on https://github.com/gtworek/Priv2Admin, I ran into a problem where it couldn't find the file I was targeting

        * I could have been more persistent and probably used this still

    * moved on to impacket/examples/secretsdump with a-whitehat login

        * (impacket/examples/secretsdump.py '\<domain\>/\<user\>:\<pass\>@\<ip\>')

        * Yielded plenty of users and hashes

        * evil-winrm back into the box with Administrator user and its password hash (-H \<hash\>)

* Grabbed system flag from this user's desktop!
---
