Original at https://ishaqmohammed.me/posts/pwk-oscp-preparation-roadmap/, updated with the different things I've read / to read 

# Resources  
## Contents  
- [ ] Repos 
- [ ] Books  
- [ ] Blogs  
- [ ] Podcasts 
- [ ] Videos 
- [ ] Services 
- [ ] [Buffer Overflow](https://github.com/Scr1ptK1ddie/OSCPprep/blob/main/Resources/BufferOverflowResources.md)    
- [ ] Tools
- [ ] Programming
- [ ] Post Shell  

## Repos  
[OSCP - Hacker's stop](https://hackerstop.org/oscp)  
[Payloadallthethings](https://github.com/swisskyrepo/PayloadsAllTheThings)     
[seclists](https://github.com/danielmiessler/SecLists)    
[Purple Team Resources](https://github.com/ch33r10/EnterprisePurpleTeaming)  
[5 Pillars to become a Cyber Security Professional](https://github.com/DFIRmadness/5pillars/blob/master/5-Pillars.md)  
[Vulnhub Resources](https://www.vulnhub.com/resources/)  
[Red Tem Resources](https://github.com/yeyintminthuhtut/Awesome-Red-Teaming)   
[Art of Hacking Repo](https://github.com/The-Art-of-Hacking/h4cker) 
[Pentesting Bible](https://github.com/blaCCkHatHacEEkr/PENTESTING-BIBLE)   

## Books 
[Red Team Field Manual](https://doc.lagout.org/rtfm-red-team-field-manual.pdf)   
[Hack Tricks](https://book.hacktricks.xyz/)  
[Dostoevskylabs's PenTest Notes](https://dostoevskylabs.gitbooks.io/dostoevskylabs-pentest-notes/)  
[Ebook Repo](https://github.com/Scr1ptK1ddie/CySecBooks)  
## Blogs  
[Trusted Security](https://www.trustedsec.com/blog/)   

## Podcasts    
[Hack the Planet](https://www.youtube.com/watch?v=xewv122qxnk)   
## Videos  

[The Cyber Mentor Youtube[(https://www.youtube.com/channel/UC0ArlFuFYMpEewyRBzdLHiw)  
[DEFCON Youtube](https://www.youtube.com/channel/UC6Om9kAkl32dWlDSNlDS9Iw)   
[IppSec Youtube[(https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA)  
[nahamsec Youtube](https://www.youtube.com/nahamsec)   
[John Hammond](https://www.youtube.com/johnhammond010)   

## Cheat sheets  
[Highoncoffee cheat sheet's](https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/)   
[Huge list of cheat sheets](https://www.reddit.com/r/cybersecurity/comments/iu17uu/cybersec_cheat_sheets_in_all_flavors_huge_list/)      
[noobsec OSCP cheatsheet](https://www.noobsec.net/oscp-cheatsheet/)       
[ceso oscp cheatsheet](https://ceso.github.io/posts/2020/04/hacking/oscp-cheatsheet/) 

## Services 
[What is Enumeration?](http://resources.infosecinstitute.com/what-is-enumeration/)    
[Common services](http://www.opsschool.org/common_services.html)  

**FTP Port 21**  
look for: anon log in, vulnerable versions  
[Pen Testing FTP](https://book.hacktricks.xyz/pentesting/pentesting-ftp)  

**SMTP Port 25**   
Possible misconfigurations and attack vectors  
[SMTP User Enumeration](https://pentestlab.blog/2012/11/20/smtp-user-enumeration/) 

**DNS Port 53 (Basics of DNS and DNS enum, DNS Zone Transfers)**  
Possible misconfigurations and attack vectors  
[DNS 101](http://www.opsschool.org/dns_101.html)  
[DNS 201](http://www.opsschool.org/dns_201.html)  
[DNS Hacking (Beginner to Advanced)](http://resources.infosecinstitute.com/dns-hacking/)  
[An Intro to DNS](https://www.digitalocean.com/community/tutorials/an-introduction-to-dns-terminology-components-and-concepts)   
[ENS Enum](https://resources.infosecinstitute.com/topic/dns-enumeration-techniques-in-linux/#gref)  

**SMB Ports 139, 445 (SMB Enumeration,Null Session Enumeration, NetBIOS)**  
Null sessions, smb vulns, other info gained
[Just what is SMB?](https://www.samba.org/cifs/docs/what-is-smb.html)  
[SMB enumeration with Kali Linux – enum4linux, acccheck and smbmap](https://hackercool.com/2016/07/smb-enumeration-with-kali-linux-enum4linuxacccheck-smbmap/)  
[Windows Null Session Enumeration](https://www.adampalmer.me/iodigitalsec/2013/08/10/windows-null-session-enumeration/)  
[NetBIOS Enumeration And Null Session](http://nrupentheking.blogspot.com/2011/02/netbios-enumeration-and-null-session.html)  
[NetBIOS and SMB Penetration Testing on Windows](http://www.hackingarticles.in/netbios-and-smb-penetration-testing-on-windows/)  
[Windows Account info via Authenticated SMB](https://www.sans.org/blog/plundering-windows-account-info-via-authenticated-smb-sessions/) 
[nbtscan Cheat Sheet](https://highon.coffee/blog/nbtscan-cheat-sheet/) 

**SNMP  (ENUMERATION, MIB Tree)**  
Possible misconfigurations and attack vectors  
[SNMP enumeration with snmpenum and snmpwalk](http://carnal0wnage.attackresearch.com/2007/07/over-in-lso-chat-we-were-talking-about.html)  

## Tools 
**Password Cracking**  
[DEF CON Password Cracking Village - Password Cracking 101](https://passwordvillage.org/general.html#hashing_vs_encryption)   

**NMAP 101 Port Scanning (TCP Connect Scan, UDP Scanning, Using NSE Scripts)**   
/usr/share/nmap/scripts 
[Hacking Articles:NMAP](http://www.hackingarticles.in/category/nmap/)  
[NMAP - Port-Scanning: A Practical Approach Modified for better](https://www.exploit-db.com/papers/35425/)   
[nmap cheat sheet](https://highon.coffee/blog/nmap-cheat-sheet/) 
[nmap: RTFM](https://blog.zsec.uk/nmap-rtfm/)   

**Wireshark 101(Capture and display filters, filters)**    
[Network Hacking 101](https://www.notion.so/Network-Hacking-101-f9137337b4854b6894753df338a3942f)   

**TCPDump (Filtering Traffic, Advanced header filtering)**  
[tcpdump cheat sheet](https://packetlife.net/media/library/12/tcpdump.pdf) 
[Tcpdump tutorial](https://danielmiessler.com/study/tcpdump/)   

**Reverse and Bind shell, Transferring Files, Types of shells(tty,pty)**  
[Netcat Tutorials for Beginner](http://www.hackingarticles.in/netcat-tutorials-beginner/)  
[Reverse Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)  
[Reverse Shell Cheat Sheet](https://highon.coffee/blog/reverse-shell-cheat-sheet/)  
[7 Linux Shells Using Built-in Tools](http://www.lanmaster53.com/2011/05/7-linux-shells-using-built-in-tools/)        
[Spawning a TTY Shell](https://netsec.ws/?p=337)  
[Upgrading simple shells to fully interactive TTYs](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/)  
[Transferring Files from Linux to Windows (post-exploitation)](https://blog.ropnop.com/transferring-files-from-kali-to-windows/)  
[Netcat without -e? No Problem!](https://pen-testing.sans.org/blog/2013/05/06/netcat-without-e-no-problem/)  
[Socat cheat sheet](https://www.redhat.com/sysadmin/getting-started-socat) 

**Recon-NG**  
[Recon cheat sheet](https://pentester.land/cheatsheets/2019/04/15/recon-resources.html) 
[Intro to Recon-ng](https://warroom.securestate.com/recon-ng-tutorial/)  
[Recon-ng: Usage Guide](https://bitbucket.org/LaNMaSteR53/recon-ng/wiki/Usage%20Guide)  

**Metasploit**   
[Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/)  
[Creating Metasploit Payloads](https://netsec.ws/?p=331)

## Web App Pentesting   
[OWASP Top 10](https://owasp.org/www-project-web-security-testing-guide/)   
[Art of Web App Pen Testing](https://github.com/The-Art-of-Hacking/h4cker/tree/master/web_application_testing)   

**1. LFI(LFI to RCE)**  
[LFI Cheat Sheet](https://highon.coffee/blog/lfi-cheat-sheet/)  
[Upgrade from LFI to RCE via PHP Sessions](https://www.rcesecurity.com/2017/08/from-lfi-to-rce-via-php-sessions/)  
[5 ways to Exploit LFi Vulnerability](http://www.hackingarticles.in/5-ways-exploit-lfi-vulnerability/)  
**2. RFI(RFI to RCE)**  
**3. SQL Injection (SQLi to RCE)**  
[Full SQL Injection Tutorial (MySQL)](https://www.exploit-db.com/papers/13045/)  
[Client Side Attacks](https://www.offensive-security.com/metasploit-unleashed/client-side-attacks/)  

## Programming
**Bash 101**  
[Bash Handbook](https://github.com/denysdovhan/bash-handbook)  
[BASH Programming - Introduction HOW-TO](http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html)  
**Python 101**  
[Python for Pentesters](http://www.pentesteracademy.com/course?id=1)  
[learnpythonthehardway](https://learnpythonthehardway.org/)  
[Practical Python](https://dabeaz-course.github.io/practical-python/)   
**Ruby 101**  
[Ruby Fu](https://rubyfu.net/)  
**Powershell**  
[PS 101](https://grimmie.net/ps-101-an-intro-to-powershell/)  
[Learning Powershell](https://github.com/PowerShell/PowerShell/tree/master/docs/learning-powershell)  
**Assembly 101**    
[Hacking the Metal: Intro to Assembly](https://github.com/eigentourist/defcon29) 
Security Tube:  
[Assembly Language Megaprimer for Linux](http://www.securitytube.net/groups?operation=view&groupId=5)  
[Windows Assembly Language Megaprimer](http://www.securitytube.net/groups?operation=view&groupId=6)  



## Post Shell 
[Fixing Exploits](https://sploitfun.wordpress.com/2015/06/26/linux-x86-exploit-development-tutorial-series/) 
[Modern Binary Exploitation](http://security.cs.rpi.edu/courses/binexp-spring2015/)  


**Privilige Escalation**  
Privilige Escalation     
[This challenge was built to promote the Windows / Linux Local Privilege](https://github.com/sagishahar/challenges#k2)        
[MySQL Root to System Root with lib_mysqludf_sys for Windows and Linux](https://www.adampalmer.me/iodigitalsec/2013/08/13/mysql-root-to-system-root-with-udf-for-windows-and-linux/)   

Linux Privilige Escalation  
[Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)  
[A GUIDE TO LINUX PRIVILEGE ESCALATION by Rashid Feroz](https://payatu.com/guide-linux-privilege-escalation/) 
[Attack and Defend: Linux Privilege Escalation
Techniques of 2016](https://www.sans.org/reading-room/whitepapers/linux/attack-defend-linux-privilege-escalation-techniques-2016-37562)   
[Abusing SUDO (Linux Privilege Escalation)](http://touhidshaikh.com/blog/?p=790)  

Windows Privilige Escalation  
[Elevating privileges by exploiting weak folder permissions](http://www.greyhathacker.net/?p=738)  
[Windows Privilege Escalation Fundamentals](http://www.fuzzysecurity.com/tutorials/16.html)  
[Windows Privilege Escalation Commands](http://pwnwiki.io/#!privesc/windows/index.md)  
[Windows 10 - Task Scheduler - Priv Esc Thru DLL Planting](http://remoteawesomethoughts.blogspot.com/2019/05/windows-10-task-schedulerservice.html) 
[DLL Proxying](https://itm4n.github.io/dll-proxying/)   
[Windows Process Injection](https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf) |  [Video for Talk](https://www.youtube.com/watch?v=xewv122qxnk)   
[Process Injection Fundamentals](https://blog.thecybersecuritytutor.com/process-injection-fundamentals/)  
[Windows Obfuscation Reference](https://www.bc-security.org/blog/)  
[Evading Detecting: A Begineer's Guide to Obfuscation](https://www.youtube.com/watch?v=lP2KF7_Kwxk)   

[Active Directory](https://adsecurity.org/)  
			 
**Pivoting / Tunneling**  	   
[SSH Tunneling Explained](https://chamibuddhika.wordpress.com/2012/03/21/ssh-tunnelling-explained/)      
[Port Forwarding in Windows](http://woshub.com/port-forwarding-in-windows/)    
[Tunneling, Pivoting, and Web Application Penetration Testing](https://www.sans.org/white-papers/36117/) 


**Post Exploitation**  
[PwnWiki.io is a collection TTPs (tools, tactics, and procedures) for what to do after access has been gained.](http://pwnwiki.io)    
[Mimikatz whitepaper](https://sansorg.egnyte.com/dl/XMHRwR5lRO/?)   




