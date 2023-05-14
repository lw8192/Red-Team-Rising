# Windows Forensics   
## Memory Analysis with Volatility     
Run strings on a memory image:   

    strings image.mem > img.strings-asc.txt	            #ASCII strings    
    strings -e l image.mem > img.strings-unile.txt      #16 bit little endian strings   
    strings -e b image.mem > img.strings-unibe.txt      #16-bit big endian strings   

Usage:   

    vol -q -f image.mem module > output.txt   
    #then analyze text files as you normally would with a live machine (ie look at the process list)   
Useful Volatility modules:     

	 windows.netscan.NetScan	#netsat info    
	 windows.pstree.PsTree	#process tree info    
	 windows.pslist.PsList		#pslist    
	 windows.cmdline.CmdLine	#command line ran of process    
	 windows.filescan.FileScan	#file objects    
	 windows.dlllist.DllList		#loaded DLLs      
	
## Command History on Windows   
Logging turned on by default: PSReadline command history, Script block logging (limited), AntiMalware Scan Interface (AMSI)   
Cmd shell history        

    doskey /h     
PSReadLine (preloaded on Windows 10)        

    Logs to C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\*.txt    
    Get-Command 
    Get-PSReadlineOption       -> HistorySavePath      
       
Module Event Logging (800 and 4103)     

    Get-WinEvent -LogName 'Windows PowerShell' -FilterXPath '*[System[(EventID=800)]]' -MaxEvents 5 | Format-Table TimeCreated, Message -Wrap
    Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -FilterXPath '*[System[(EventID=4103)]]' -MaxEvents 5 | Format-Table TimeCreated, Message -Wrap

Script block logging (event ID 4104) 

    Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -FilterXPath '*[System[(EventID=4104)]]' -MaxEvents 5 | Format-Table TimeCreated, Message -Wrap
Transcript Logging (logging location can change)       

    Select-String -Path C:\PSTranscripts\*\* -Pattern 'malware'

AMSI: scans script prior to execution in newer versions of Windows     

    Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -FilterXPath "*[System[((EventID=1116) or (EventID=1117))]]" -MaxEvents 5 | Format-Table TimeCreated, Message -Wrap      
   
## Windows Logging   
Windows: event logs as evtx files (open in Event Viewer or use PowerShell to query).     
%System32%/Winevt/Log    
Application Log    
System and Security Logs     

Event IDs to monitor for possible malware: 4624, 4634, 4672, 4732, 4688, 4697     
AppLocker: application allow listing in Windows. Event ID 8004: executables blocked by AppLocker.        
    
    PS > Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' | Where-Object -Property Id -EQ 8004	
## RDP History    

    PS > qwinsta        #current remote sessions     
    PS > get-winevent -logname "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"    
    
Registry RDP Connection Cache 

    HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client
    2 registry keys in this section: Default (history of the last 10 RDP connections) and Servers (all RDP servers and usernames used previously to login)     
    
## USB Devices   
Ref: https://www.sciencedirect.com/topics/computer-science/window-registry    
All USB devices ever plugged in    

    PS > gci HKLM:\SYSTEM\CURRENTCONTROLSET\ENUM\usbstor	   
Drives mounted to NTFS file system   

    PS > gi HKLM:\SYSTEM\MOUNTEDDEVICES	      
User logged in when specific device was plugged in       

    PS > gci HKCU:\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\MOUNTPOINTS2			
USB device interface GUID, hardware ID, device class information about your device, and the last time this USB was connected to the current machine    
    
    PS > gci HKLM:\SYSTEM\CURRENTCONTROLSET\ENUM\USB    
 Newer Windows, search for USB serial number to see when connected     
 
    C:\Windows\inf\setupapi.dev.log    
    PS > type C:\Windows\inf\setupapi.dev.log | findstr Section   #search for string 
  
## Timestomping   
Find possible malware by looking for timestamps that were changed.    
Key indicators of timestomping on Windows: 
- When the subseconds in the $MFT’s 0x10 timestamps is .000000. Some automated tools do not change these (like Metasploit). 
- If the 0x10 timestamp appears to occur before a 0x30 $MFT timestamp
- If the context of a file relating to its name, parent folder or other file details is inconsistent
- Comparing the $STANDARD_INFORMATION timestamps vs the $FILE_NAME timestamps in the Master File Table (MFT). 
C - creation. CreationTime and CreationTimeUtc    
W - last modified. LastWriteTime, LastWriteTimeUtc      
A - last accessed. LastAccessTimeUtc, LastAccessTime       
 
    PS > (Get-Item c:\file.txt).lastwritetime | select *     
    PS > Get-Item file.txt | select name,lastwritetime, lastaccesstime, lastcreationtime    
