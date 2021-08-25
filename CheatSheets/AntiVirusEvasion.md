# AV Evasion   
## Notes 
2 primary types: 
on disk: file saved on target then executed 
in memory: preferred for evasion, import script into memory and then executed.  
Windows AMSI (Anti Malware Scan Interface): evals commands at runtime, scans scripts as they are imported into memory, makes evasion harder. VBA, Powershell, JavaScript. 
 AV agnostic: API any anti-virus product can use. "Identify fileless threats - at runtime most of obfuscation is removed" defeat: obfuscate code. 


## Tools     
Testing: [Windows developer iso](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/)  

[Invoke-Obfuscation powershell script](https://github.com/danielbohannon/Invoke-Obfuscation)  
[Invoke-bfuscation Usage Guide](https://www.danielbohannon.com/blog-1/2017/12/2/the-invoke-obfuscation-usage-guide)  
https://github.com/tokyoneon/Chimera ( bypassing AMSI and signature based detection )   
https://github.com/persianhydra/Xeexe-TopAntivirusEvasion   
https://github.com/BC-SECURITY/Empire/blob/master/empire/server/common/bypasses.py  



## Commands 
Turning off Windows Defender 

    Set-MpPreference -DisableRealtimeMonitoring $true   

Need to run Powershell as admin and reboot after running command to turn off Windows Defender: 

    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -name disableantispyware -value 1 -Force


View Windows Defender logs   

    Get-WinEvent 'Microsoft-Windows-Windows Defender/Operational' MaxEvents 10 | Where-Object Id -e 1116 | Format-List 


# Resources  
## Cheat sheets 
https://github.com/sinfulz/JustEvadeBro   
https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell

## Workshops 
https://github.com/BC-SECURITY/Beginners-Guide-to-Obfuscation 



