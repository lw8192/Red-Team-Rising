# BloudHound Cheatsheet     
[BloodHound](https://github.com/BloodHoundAD)    
## Start  

    service neo4j start
    http://localhost:7474/
## On Target   
Sharphound builds[here](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors)    
## Upload Sharphound.ps1 and run using PowerShell   

    .\SharpHound.ps1
    Invoke-BloodHound -CollectionMethod All -OutputDirectory .    
### SharpHound.exe     

    .\SharpHound.exe --CollectionMethod All --domain <DOMAIN>    
### Within Meterpreter  

    load powershell
    powershell_execute "Invoke-BloodHound -CollectionMethod All -OutputDirectory ."
## Analyze Results   
On attack box:   

    bloodhound
    drag& drop the transferred zip file    
