# Add `contain-linux.thm` to `/etc/hosts`
Add the target hostname to your attacker machine's `/etc/hosts` file (root required).

`echo "<IPv4 address of target hostname> contain-linux.thm" >> /etc/hosts` (Attacker Machine)
# Active Scanning / Network Discovery
First and foremost, run a full port scan with Nmap to find open ports, services, and versions.

`nmap -A -p- -sC -sV contain-linux.thm` (Attacker Machine)

The scan returns an open SSH service on default TCP port 22 and an open HTTP service on default port 80.
# Web Enumeration (Port 80)
Enumerate directories and files on the web server using gobuster.

`gobuster dir -u http://contain-linux.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,htm,txt` (Attacker Machine)

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
