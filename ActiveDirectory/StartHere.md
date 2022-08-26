# Active Directory Cheatsheet     
## Active Directory Overview 
To gain control over a domain:  
Compromise member of Domain Admin group.   
Compromise domain controller -> can modify all domain-joined computers or execute applications on them. 

AD: depends on DNS server, typical DC hosts DNS server that is authoritative for a given domain. 
Authentication mechanisms: Kerberos or NTLM 

Typical AD pen test:
- Exploit host on domain and gain access  as a domain user 
- Enumerate domain users and groups.  
- Privilege escalate or move laterally. 
- Get Domain Admin or Service Account access and onto the domain controller. 

## My AD Cheatsheets
 

## Resources      
[WADComs](https://wadcoms.github.io/)    

## Other Cheat Sheets
[AD Cheat Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)     
[AD Lateral Movement and Persistence Cheatsheet](https://bhanusnotes.blogspot.com/2020/12/ad-pentest-lateral-movement-persistance.html)  
[AD Cheat sheet](https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference/)   
[Pentesting AD CheatSheet](https://i.ibb.co/TKYNCNP/Pentest-ad.png)  
[Integratio IT Cheat Sheet](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet)  

    
### Important Files to Check on the DC
    %SYSTEMROOT%\System32\ntds.dit             #AD database
    %SYSTEMROOT%\NTDS\ntds.dit                 #AD backup

## Tools  
### Tools allowed on the new exam 
All tools that do not perform any restricted actions are allowed on the exam (no commercial tools like Burp Pro, no automated exploits like SQLmap, etc).   

    [BloodHound](https://github.com/BloodHoundAD/BloodHound)     
    [SharpHound](https://github.com/BloodHoundAD/SharpHound)    
    [PowerShell Empire](https://github.com/BC-SECURITY/Empire)    
    Covenant 
    Powerview
    Rubeus
    [evil-winrm](https://github.com/nubix/evil-winrm): access Windows RM, TCP port 5985 or 5986 open.   
    Responder (Spoofing is not allowed in the labs or on the exam)
    Crackmapexec
    Mimikatz

## General Tools 

[Impacket](https://github.com/SecureAuthCorp/impacket): collection on Python classes for working with network protocols.       

    #if not properly installed 
    apt install impacket-scripts  
    /usr/share/doc/python3-impacket/examples  
    
[ADSC-Pwn](https://github.com/bats3c/ADCSPwn)   

 
# Resources
[Active Directory Security 101 Class](https://github.com/cfalta/adsec) 

https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse
 
[Understanding Windows Lateral Movement](https://attl4s.github.io/assets/pdf/Understanding_Windows_Lateral_Movements.pdf)  

[PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#most-common-paths-to-ad-compromise)

[Attacking Active Directory: 0 to 0.9](https://zer1t0.gitlab.io/posts/attacking_ad/)

[Active Directory Enumeration | ATTL4S](https://attl4s.github.io/assets/pdf/Understanding_Active_Directory_Enumeration.pdf) 

[Adsecurity Blog](https://adsecurity.org/) 

[RedTeam Security Live Hacking Demonstration](https://www.youtube.com/watch?v=k6EOhO3JKCQ) 

[NetNTLMtoSilverTicket | NotMedic's Github](https://github.com/NotMedic/NetNTLMtoSilverTicket) 
