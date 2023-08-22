## Mindgames

---

Tags:

Tools:

Process:

* Firstly, I add `<target ip>\t<target hostname>` to "/etc/hosts"

* Then I begin with my usual nmap scan.

    * There is an open ssh server and a webserver. I start a more expanded scan in the background while I move on just in case I missed anything.

* I move on to the webserver which has a landing page containing an apology and some brainfuck code (This is a programming language). One code snippet is a hello world and the other is a recursive fibonacci calculator (I verified on dcode.fr). There is also a textarea to input code and a "Run It!" button that doesn't seem to work.

* I begin subdirectory enumeration on the webserver with dirb and use burpsuite to analyze the website behavior.

*Neither the extended port scan or the subdirectory enumeration scan came back with nothing*

* Burp doesn't show anything too interesting. However, entering brainfuck code in the textarea and clicking the button executes the code.

* The encoded/decoded (not brainfuck) code seems to follow python syntax so I'm trying to get a reverse shell to execute by encoding python payloads into brainfuck on dcode.fr and running the brainfuck code on the site.

    * One other thought I have is that I could try to curl/wget a shell onto the box and then navigate to `<url>/<revshell>`.

    * My initial method worked. I was including the "python3" portion of the command when I obviously shouldn't have because it had to already be running a python instance to execute the code.

* Now I have a shell and a user flag!

* I'm beginning to enum privesc vectors. I start with the standards such as `sudo -l`, `id`, find suid binaries, etc. and find nothing manually.

    * Next I'll upload linpeas and see if that shows me anything. I host a temporary python webserver on my kali machine, wget it onto the target, chmod +x it, and run it.

* I'll follow an exploit from an article on github to abuse the openssl suid cap for privesc.

* This worked and I'm root now! Grab the flag!