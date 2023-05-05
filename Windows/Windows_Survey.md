# Windows Survey Commands   
Commands to survey a box or look for malicious activity.    

## Processes    
Suspicious processes: look for weird names or activity, non-standard path, weird parent / child relationships, base64 encoded command line options.         

    PS > Get-Process 'name*' | select -object *   
    PS > Get-Process -ComputerName Remote     #get process info from a remote computer   
    PS > Get-CimInstance -Class win32_process | select-object ProcessId, ProcessName,CommandLine   #more detailed info 
    PS > Get-CimInstance -Class win32_process | Where-Object -Property ParentProcessID -EQ 644  #parent proc info  
    
## Services 

    net start                         #installed and started services 
    wmic service where "name like 'service'" get Name,PathName        #more info on a service 
    PS > Get-Process -Name service  

## Network Usage    
Suspicious connections: look for multiple outbound connections, strange behavior, long HTTP or HTTPS sessions, techniques or known malicious IOCS. 
    PS > Get-NetTCPConnection -State Listen | Select-Object -Property LocalAddress, LocalPort, OwningProcess   
    PS > Get-NetTCPConnection -RemoteAddress 192.168.10.0 | Select-Object CreationTime, LocalAddress, LocalPort, Remote Address, RemotePort, OwningProcess, State    #info from a remote system   
    PS > Get-Process -ID pid    #get PID from netstat then lookup process   
 
 ## Firewalls    
 
    netsh firewall show state 
    netsh firewall show config   
    PS > Get-NetFirewallProfile | Format-Table Name, Enabled  
    PS > Get-NetFirewallRule | select DisplayName, Enabled, Description #firewall rules 
    PS > Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False       #disable firewall (if admin)   
