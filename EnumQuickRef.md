# Quick Reference for Enumerating Network / Host / Services
## Recon   
### Network Enum:  
Ping sweep:   
for x in {1 .. 254};do (ping -c 1 l.l.l.$x | grep "bytes from" &); done | cut -d " "
Port Forwading:


### Host enum:   
**Identify os, services/ports/versions. Save results to text files. **   

autorecon <ip>  
	results/[ip]/scans   
	_quick_tcp_nmap.txt		_patterns.log		_manual_commands.txt

nmap -A -T 4  
nmap -sV -p-   

nc -nvzw1 192.168.53.120 1-65535 2>&1 | grep open       

### Service Enum   

nmap scripts: /usr/share/nmap/scripts   
nmap --script <name>    --script-help 
	
**Port 21: FTP**
	[Enumerating ftp](https://book.hacktricks.xyz/pentesting/pentesting-ftp)   
	
	anon log in: ftp / no password	or 	Anonymous: asdfasdf
	
**Port 25: SMTP**   
	
	smtp-user-enum -M VRF -u <user.txt> -t <ip>
