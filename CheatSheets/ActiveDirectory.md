# Active Directory Cheatsheet  
[WADComs](https://wadcoms.github.io/)   

## Kerberos (Port 88)   
[Kerbrute](https://github.com/ropnop/kerbrute), [Rubeus](https://github.com/GhostPack/Rubeus)   
Kerberoasting  



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
    




