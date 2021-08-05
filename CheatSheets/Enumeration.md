# Enumeration Quick Reference 
## Checklist 
- [ ] Recon 
- [ ] (If given a range): what hosts are on the network
- [ ] Open well known ports (0-1023)
- [ ] What are these ports used for (banner grab) 
- [ ] Open high ports (12024-65535) 
- [ ] Operating system 
- [ ] FTP or SMB anon log in 
- [ ] Exploitable services versions (searchsploit, github, google) 
- [ ] Web enum (see checklist below) 
- [ ] Brute force any services / log in pages 

## Recon   
### DNS Look Up 
whois, nslookup, dig, host <-manual tools   
Dierce, DNSenum, DNSrecon <-automated tools  

    nslookup -type=any <DOMAIN>   
    host -t axfr -l <DOMAIN> <DNSSERVER>   
    dig -t mx <DOMAIN>  
    dig -t any <DOMAIN>
    
## Network Enum:  
    for x in {1 .. 254};do (ping -c 1 l.l.l.$x | grep "bytes from" &); done | cut -d " "    
    nmap -sn 172.16.0.0/24 

## Host enum 
**Identify os, services/ports/versions. Save results to text files. **   

    autorecon 127.0.0.1  
    nmap -A -T 4 -vv 127.0.0.1
    nmap -sV -p- --min-rate 200 -vv 127.0.0.1  

    nc -nvzw1 192.168.53.120 1-65535 2>&1 | grep open       

## Service Enum   

nmap scripts: /usr/share/nmap/scripts   
nmap --script <name>    --script-help 
	
**Port 21: FTP**
[Enumerating ftp](https://book.hacktricks.xyz/pentesting/pentesting-ftp)   
	
	anon log in: ftp / no password	or 	Anonymous: asdfasdf 
	
**Port 25: SMTP**   
	
	smtp-user-enum -M VRF -u <user.txt> -t <ip> 
	
**Port 139: SMB** 
	
    smbclient -L <IP>
    rpcclient -U "" <IP>
    smbclient -U <HOST> -L <IP>
    /usr/bin/smbclient \\\\<IP>\\share <HOST>
	
## Web Enum 
- [ ] Scan for sub directories and pages 
- [ ] Log in pages - guess default creds, admin:admin, admin:password 
- [ ] File upload (what types of files are accepted) 
- [ ] Intercept HTTP requests with Burp 	
	
	
    nmap http scripts 
	
    nikto -h http://127.0.0.1:80/ 
	
    dirb http://127.0.0.1/   (default word list: common.txt) 
