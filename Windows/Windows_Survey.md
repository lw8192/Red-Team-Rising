# Windows Survey Commands   
Commands to survey a box or look for malicious activity.    
Common persistence methods: services, scheduled tasks, autoruns, startup folders, WMI events.   

- [Windows Survey Commands](#windows-survey-commands)
  * [Network Usage](#network-usage)
  * [Processes](#processes)
  * [Services](#services)
  * [Registry](#registry)
  * [User Accounts](#user-accounts)
  * [Scheduled Tasks](#scheduled-tasks)
  * [WMI Events](#wmi-events)
  * [Firewalls](#firewalls)
  * [Binary Analysis](#binary-analysis)
  * [SMB Shares](#smb-shares)
  
## Network Usage    
Suspicious connections: look for multiple outbound connections, strange behavior, long HTTP or HTTPS sessions, techniques or known malicious IOCS.     
Network traffic indicators: long connections, consistent packet intervals, consistent data sizes (heartbeat checking), consistent packet intervals within a jitter metric (skew)       

    netstat.exe -nao
    PS > Get-NetTCPConnection -State Listen | Select-Object -Property LocalAddress, LocalPort, OwningProcess   
    PS > Get-NetTCPConnection -RemoteAddress 192.168.10.0 | Select-Object CreationTime, LocalAddress, LocalPort, Remote Address, RemotePort, OwningProcess, State    #info from a remote system   
    PS > Get-Process -ID pid    #get PID from netstat then lookup process   
    
## Processes    
Suspicious processes: look for weird names or activity, non-standard path, weird parent / child relationships, base64 encoded command line options.         

    wmic.exe process   
    PS > Get-Process 'name*' | select -object *   
    PS > Get-Process -ComputerName Remote     #get process info from a remote computer   
    PS > Get-CimInstance -Class win32_process | select-object ProcessId, ProcessName,CommandLine   #more detailed info 
    PS > Get-CimInstance -Class win32_process | Where-Object -Property ParentProcessID -EQ 644  #parent proc info  
    
## Services 
Services: common persistence method.   

    net start                         #installed and started services 
    sc.exe query 
    wmic service where "name like 'service'" get Name,PathName        #more info on a service 
    PS > Get-Process -Name service  
    PS > Get-CimInstance -ClassName win32_service | Format-List Name,Caption,Description,PathName   #get path to program
    #view logs: new service installed
    wevutil.exe  
    PS > Get-WinEvent -LogName System | Where-Object -Property Id -EQ 7045 | Format-List -Property TimeCreated, Message
 ## Registry   
 HKLM and HKCU are hives on disk. Look for autoruns (ASEP) and startup folders.      
 
     reg.exe  
     PS > Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' | Select-Object PSChildName
     PS > Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'   #local machine startup 
     PS > Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' 
     PS > Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'   #user startup
     PS > Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' 
   
 ## User Accounts 
 Look for new weird accounts in the admins group.    
 
     net.exe user  
     net.exe localgroup 
     PS > Get-LocalGroup Administrators   
     
 ## Scheduled Tasks 
 
     schtasks.exe 
     PS > Get-ScheduledTask *Name* | Select-Object -Property TaskName    
     PS > Export-ScheduledTask -TaskName 'Name'   #get more info 
     PS > Get-ScheduledTaskInfo -TaskName 'Name' | select-object LastRunTime    #see last time ran
## WMI Events  

    PS > Get-WMIObject -Namespace root\Subscription -Class __EventFilter | fl -propertyquery #look for WMI persistence mechanisms     
    
## Firewalls    
 
    netsh firewall show state 
    netsh firewall show config   
    PS > Get-NetFirewallProfile | Format-Table Name, Enabled  
    PS > Get-NetFirewallRule | select DisplayName, Enabled, Description #firewall rules 
    PS > Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False       #disable firewall (if admin)   
    
## Binary Analysis 
Pull binary and associated files for further analysis in a sandbox. Collect memory (if able / applicable).   

    PS > Get-FileHash file     #sha256 hash  
    PS > strings file          #using SysInternals tool 
    PS > winpmem_mini.exe image.raw     #perform a memory capture 
    
## SMB Shares   
View remote shares:   

     PS > Get-WmiObject -Class win32_share -ComputerName ip         
     net view /all \\server 
View local shares: 

     PS > Get-SMBShare                                                                               
     net share 
Connect SMB share:    

    PS:> New-SmbMapping -LocalPath X: -RemotePath \\server\sharename     
    net use \\server\sharename 
View inbound connections:   

    PS:> Get-SmbSession                                                             
    net session 
Drop inbound connections:   

    PS:> Close-SmbSession                                                               
    net session \\server /del   
View outbound SMB mapped connections: 

    PS:> Get-SmbMapping                                        
    net use 
Drop outbound SMB connections:    

    PS:> Remove-SmbMapping -Force                                     
    net use * /del    
    
 ## Logging 
 Event Ids to check for persistence: 4624, 4634, 4672, 4732, 4688, 4697   
