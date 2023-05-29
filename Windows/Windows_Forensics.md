# Windows Forensics   
[DFIR Cheatsheet](https://www.13cubed.com/downloads/dfir_cheat_sheet.pdf)     
[Registry Key Quick Find Chart](https://www.offsec.com/wp-content/uploads/2015/04/wp.Registry_Quick_Find_Chart.en_us.pdf)   
[DFIR iBlue Wiki](https://www.iblue.team/)    
## PowerShell Reference    
Helpful Cmdlets     

    Get-Help   
    Get-Content    
    Get-ChildItem     
Output Modifiers   

    Out-GridView   
    ConvertTo-Csv    
    Format-Table    
    ConvertTo-Html    
    ConvertTo-Json   
    ConvertTo-Xml      
    
## Sysinternals    
Process explorer: running processes.      
Autoruns: autostart extensibility points (ASEP).     
Process monitor: files, registry, network, proc info.     
Sysmon: event info for system monitoring and analysis.     
TCPview: view TCP and UDP activity of programs.    
ProcDump: capture memory of a running process for analysis.    

## Memory Analysis with Volatility     
https://infosecwriteups.com/forensics-memory-analysis-with-volatility-6f2b9e859765    
[Volatility Usage](https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage)    
Run strings on a memory image:   

    strings image.mem > img.strings-asc.txt	            #ASCII strings    
    strings -e l image.mem > img.strings-unile.txt      #16 bit little endian strings   
    strings -e b image.mem > img.strings-unibe.txt      #16-bit big endian strings   

Usage:   

    vol -q -f image.mem module > output.txt   
    #then analyze text files as you normally would with a live machine (ie look at the process list)   
    vol.py -f memdump.elf --profile=Win7SP1x64 filescan > filescan.txt     #example with profile   

Useful Volatility modules:     
[Truecrypt Modules](https://volatility-labs.blogspot.com/2014/01/truecrypt-master-key-extraction-and.html)    

	 windows.netscan.NetScan	#netsat info    
	 windows.pstree.PsTree	        #process tree info    
	 windows.pslist.PsList		#pslist    
	 windows.cmdline.CmdLine	#command line ran of process    
	 windows.filescan.FileScan	#file objects    
	 windows.dlllist.DllList	#loaded DLLs     
	 pslist, psscan, pstree, psxview     #processes  
	 truecryptsummary, truecryptpassphrase, truecryptmaster   #truecrypt plugins   
	
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
[Collection of Event IDs](https://github.com/stuhli/awesome-event-ids)    
Windows: event logs as evtx files (open in Event Viewer or use PowerShell to query).     
System Log: %systemroom%\System32\WinEvt\Logs\System.evtx    
Security Log: %systemroot%\System32\WinEvt\Logs\Security.evtx    
Application Log: %systemroot%\System32\WinEvt\Logs\Application.evtx    
Setup Logs: %systemroot%\System32\WinEvt\Logs\Setup.evtx     
   
Event IDs to monitor for possible malware: 4624, 4634, 4672, 4732, 4688, 4697     
AppLocker: application allow listing in Windows. Event ID 8004: executables blocked by AppLocker.        
    
    PS > Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' | Where-Object -Property Id -EQ 8004	
    
## Registry    
5 root keys:HKEY_CURRENT_USER, HKEY_USERS, HKEY_LOCAL_MACHINE, HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG       
HKCU: config info for currently logged in user. Subkey of HKU.         
HKU: all actively loaded user profiles.    
HKLM: config info for the machine.      
HKCR: subkey of HKEY_LOCAL_MACHINE\Software, config info for programs to be opened.      
HKCC: hardware profile used by the computer at startup.    

Registry hives located on disk in C:\Windows\System32\Config      

    DEFAULT (mounted on HKEY_USERS\DEFAULT)      
    SAM (mounted on HKEY_LOCAL_MACHINE\SAM)          
    SECURITY (mounted on HKEY_LOCAL_MACHINE\Security)     
    SOFTWARE (mounted on HKEY_LOCAL_MACHINE\Software)     
    SYSTEM (mounted on HKEY_LOCAL_MACHINE\System)     
Amcache Hive      

C:\Windows\AppCompat\Programs\Amcache.hve. Windows creates this hive to save information on programs that were recently run on the system.      
Some Important Registry Keys      
Computer Name        
SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName     

Time Zone Info      
SYSTEM\CurrentControlSet\Control\TimeZoneInformation        

Network Interfaces and Past Networks     
SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces        

## RDP History    

    PS > qwinsta        #current remote sessions     
    PS > get-winevent -logname "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"    
    
Registry RDP Connection Cache     

    HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client
    2 registry keys in this section: Default (history of the last 10 RDP connections) and Servers (all RDP servers and usernames used previously to login)     

RDP Cache    
Cache files are created containing the sections of the server machine screen. Use a tool to extract images stored in file.     

    C:\Users\XXX\AppData\Local\Microsoft\Terminal Server Client\Cache

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
    
## Analyzing Malicious Documents     
[SANS Oledump Cheatsheet](https://www.sans.org/posters/oledump-py-quick-reference/)    
[Analyzing Malicious Docs Cheatsheet](https://zeltser.com/analyzing-malicious-documents/)   
Binary Microsoft Office document files (.doc, .xls, etc.) use the OLE2 (a.k.a. Structured Storage) format.   
OOXML document files (.docx, .xlsm, etc.) supported by Microsoft Office are compressed zip archives.    
VBA macros in OOXML documents are stored inside an OLE2 binary file, which is within the zip archive.     

    oledump.py file.doc -i   #list OLE2 streams. M - means stream is a macro          
    oledump.py -s 3 -S file.doc                #string dump of OLE stream  
    oledump.py -s 11 -v file.doc  #extract VBA code from stream 11
    oledump.py -s 3 --vbadecompresscorrupt file.doc       #recover macro    
    
Extract:    

 rename to .zip, extract. docx - zip files with stream docs inside for further analysis.    
