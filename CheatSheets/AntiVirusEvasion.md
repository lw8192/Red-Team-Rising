# AV Evasion   
## Notes 
2 primary types: 
on disk: file saved on target then executed 
in memory: preferred for evasion, import script into memory and then executed.  
Windows AMSI (Anti Malware Scan Interface): evals commands at runtime, scans scripts as they are imported into memory, makes evasion harder. VBA, Powershell, JavaScript. 
 AV agnostic: API any anti-virus product can use. "Identify fileless threats - at runtime most of obfuscation is removed" defeat: obfuscate code. 


https://github.com/BC-SECURITY/Empire/blob/master/empire/server/common/bypasses.py  


[Invoke-Obfuscation powershell script](https://github.com/danielbohannon/Invoke-Obfuscation)  
[Invoke-bfuscation Usage Guide](https://www.danielbohannon.com/blog-1/2017/12/2/the-invoke-obfuscation-usage-guide)  







# Resources
https://offensivedefence.co.uk/posts/making-amsi-jump/   
https://i.blackhat.com/briefings/asia/2018/asia-18-Tal-Liberman-Documenting-the-Undocumented-The-Rise-and-Fall-of-AMSI.pdf   
https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell  
https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/amsi_patch_bin.nim  
https://blog.f-secure.com/hunting-for-amsi-bypasses/  
https://www.contextis.com/us/blog/amsi-bypass  
https://www.redteam.cafe/red-team/powershell/using-reflection-for-amsi-bypass  
https://amsi.fail/  
https://rastamouse.me/blog/asb-bypass-pt2/  
https://0x00-0x00.github.io/research/2018/10/28/How-to-bypass-AMSI-and-Execute-ANY-malicious-powershell-code.html  
https://www.youtube.com/watch?v=F_BvtXzH4a4  
https://www.youtube.com/watch?v=lP2KF7_Kwxk  
https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/  



