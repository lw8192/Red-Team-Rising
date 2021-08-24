# AV Evasion   
## Notes 
2 primary types: 
on disk: file saved on target then executed 
in memory: preferred for evasion, import script into memory and then executed.  
Windows AMSI (Anti Malware Scan Interface): evals commands at runtime, scans scripts as they are imported into memory, makes evasion harder. VBA, Powershell, JavaScript. 
 AV agnostic: API any anti-virus product can use. "Identify fileless threats - at runtime most of obfuscation is removed" defeat: obfuscate code. 


https://github.com/BC-SECURITY/Empire/blob/master/empire/server/common/bypasses.py  

## Tools  
[Invoke-Obfuscation powershell script](https://github.com/danielbohannon/Invoke-Obfuscation)  
[Invoke-bfuscation Usage Guide](https://www.danielbohannon.com/blog-1/2017/12/2/the-invoke-obfuscation-usage-guide)  
https://github.com/tokyoneon/Chimera ( bypassing AMSI and signature based detection )
https://github.com/persianhydra/Xeexe-TopAntivirusEvasion


## Commands 
Turning off Windows Defender 

    Set-MpPreference -DisableRealtimeMonitoring $true   
    
    set HKLM/SOFTWARE/Policies/Microsoft/Windows Defender/DisableAntiSpyware to 1





# Resources  
## Cheat sheets 
https://github.com/sinfulz/JustEvadeBro   
https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell





