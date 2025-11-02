# Add `contain-linux.thm` to `/etc/hosts`
Add the target hostname to your attacker machine's `/etc/hosts` file (root required).

`echo '<IPv4 address of target hostname> contain-linux.thm' >> /etc/hosts`
# Active Scanning / Network Discovery
First and foremost, run a full port scan with Nmap to find open ports, services, and versions.

`nmap -A -p- -sC -sV contain-linux.thm`

The scan returns an open SSH service on default TCP port 22 and an open HTTP service on default port 80.
# Web Enumeration (Port 80)
Enumerate directories and files on the web server using gobuster.

`gobuster dir -u http://contain-linux.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,htm,txt`

This enumeration discovers a file named \<redacted\> on the webroot.
# Decoding File Content
The retrieved file contains encoded data written in the Brainfuck esoteric language. Decode that content using an online decoder.

[Brainfuck Language](https://www.dcode.fr/brainfuck-language)

The decoded string provides a private SSH key.
