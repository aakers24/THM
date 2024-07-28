## New York Flankees

---

Tags: Linux, Padding Oracle, Docker

Tools: nmap, ssh, padbuster, padre

Process:

* I started with my usual scans using nmap which showed SSH & a Web server, and then gobuster/dirb which didn't show anything.

* The landing page for the web server has test and login buttons, as well as references to cryptography and oracle.

    * The page source has some interesting stuff, including a script section which shows that you get a different button instead of the admin login page if you have the "loggedin" cookie. Creating that cookie works and the button changes.

* The new button leads to a blank page, but going to the test page gives interesting information and the page source code also has some very important information. The script here is very telling. Using hints there you can get a successfully authenticated login.

* Using this inforamtion and some hints from before, I googled for Oracle Padding and found the `padbuster` tool.

    * I tried using this tool, but clearly I'm doing something wrong. I tried brute-forcing different block sizes and nothing worked. I found some documentation on someone using it with 

* After doing some more searches for tools, I found padre on GitHub. It seems to be more hands-off and user-friendly. It may be beneficial to figure out how to get the padbuster solution to work, but I don't want to spend more time on it.

* Once I got all of the parameters for the padre tool right it worked!

* I first used these creds to log in to the admin portal on the website.

    * I also used the cred to try to log into the SSH server, but it didn't work.

    * On the admin panel, it worked and I got a flag and a command line.

* I tried some commands and got 200 response codes on valid commands. I hosted a python server locally with `python -m http.server <port>` and downloaded my bash shell through the admin panel using the curl command and directing the output file to /tmp/. I then ran the chmod +x command on it through that admin panel, and finally ran the shell through the panel.

* I got a root shell on my listener!

* This is a docker container, which is evident from the .dockerenv file in the root directory.

    * There is another flag in the /app/docker-compose.yml file.

* I googled "break out of docker" and remembered that linpeas enumerates breakout vectors so I curled it down and ran linpeas.

    * I actually just ended up running the first command on the hacktricks page that is the first page that showed up on google and is the one I got the linpeas idea from. As it turns out, that first command works and this is the way I break out.

    * What I did exactly was-

        * `find / -name docker.sock 2>/dev/null` to confirm the presence of the file.

        * Then `docker images` to see the list of images to choose from.

        * `docker run -it -v /:/host/ <image> chroot /host/ bash` *I had to make the shell a tty using python to get this command to work*

* After this I was broken out and got the final flag!