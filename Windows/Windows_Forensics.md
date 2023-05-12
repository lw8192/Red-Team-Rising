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
