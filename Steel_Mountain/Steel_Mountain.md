## Steel Mountain

---

Tags: Windows, unquoted service, modifiable service

Tools: nmap, metasploit, msf, exploit-db, cve, PowerSploit, Powershell, msfvenom, netcat, revshell

Process:

##### *This is a walkthrough room so some of these notes will be redundant if following the actual room. I am just trying to get reps in and lock in my note-taking as well as windows pentesting process.*

* nmap scan shows 11 open ports including 80

* check the other webserver and note what service it's running

* exploit-db

* msfconsole: search cve from previous bullet point, use this module, set the options, exploit

* navigate to user flag and collect it

* Clone the PowerSploit suite and upload the PowerUp.ps1 script to the target machine

* In meterpreter shell, "load powershell", "powershell_shell"

* In this new ps shell, run the script and Invoke-AllChecks

* There is one service with a modifiable file and CanRestart true

    * This means I can replace the file because the dir is writable and the CanRestart True means I can restart the service and get it to run

    * The path is unquoted which is another attack vector

* Use msfvenom to create a payload with the same file name as the target executable

* sc stop \<service\>

* upload payload to replace the service executable

* open a shell listener

* sc start \<service\>

* I am system!

* Navigate to root flag and write it to console (equivalent of cat) with "type \<file\>"

*This Box is also doable without metasploit. There are different exploits using the same CVE. You can use a revshell listener instead of msf. The service is findable manually with powershell -c get-service.*

---