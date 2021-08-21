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
- [ ] Web enum (see WebEnumeration.md cheatsheet) 
- [ ] Brute force any services / log in pages   

[Enumeration Mind Map](https://github.com/theonlykernel/enumeration/wiki)     

## Recon   
### OSINT   
[OSINT Tools](https://www.osinttechniques.com/osint-tools.html)  <- List of OSINT tools for any occassion   
[The Harvester](https://github.com/laramies/theharvester)    <- gathers emails, names, subdomains, IPs and URLs      
[Recon-ng](https://github.com/lanmaster53/recon-ng)  <- Recon framework
[hunter.io](https://hunter.io/)       <- find email addresses for a company    

### DNS Look Up 
whois, nslookup, dig, host <-manual tools   
Dierce, DNSenum, DNSrecon <-automated tools  

    nslookup -type=any <DOMAIN>   
    host -t axfr -l <DOMAIN> <DNSSERVER>   
    dig -t mx <DOMAIN>  
    dig -t any <DOMAIN>
    
## Network Enum:  
    for x in {1 .. 254};do (ping -c 1 l.l.l.$x | grep "bytes from" &); done | cut -d " "     
    nmap -v -s 192.168.0.0/24   
    nmap -Pn -vv -F -sSU -T4 -oG /kali/192.168.15.200-254.xml 192.168.15.200-254 | grep -v 'filtered|closed' > /kali/quick_recon.txt         

## Host enum 
**Identify os, services/ports/versions. Save results to text files. **   

    autorecon 127.0.0.1 --only-scans-dir -v      
    nmap -A -T 4 -vv 127.0.0.1    
    nmap -sV -p- --min-rate 200 -vv 127.0.0.1     

    nc -nvzw1 192.168.53.120 1-65535 2>&1 | grep open       

## Service Enum   

nmap scripts: /usr/share/nmap/scripts   
nmap --script <name>    --script-help 
	
**Port 21: FTP**  
	
[Enumerating ftp](https://book.hacktricks.xyz/pentesting/pentesting-ftp)   
	
	anon log in: ftp / no password	or 	Anonymous: asdfasdf           
	nmap -sV -Pn -vv -p 21 --script=ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221     
    hydra -C ftp/usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -u 127.0.0.1 ftp    
	
**Port 25: SMTP**   
	
	smtp-user-enum -M VRF -u <user.txt> -t 127.0.0.1   
	nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 127.0.0.1  
	
**Port 389: LDAP**  
	
	ldapsearch -h 127.0.0.1 -p 389 -x -s base
	
**Port 139: SMB** 
check for unauthenticated login, enum with smbmap 
	[Eternal Blue](https://github.com/3ndG4me/AutoBlue-MS17-010)  
	
    smbclient -L <IP>
    rpcclient -U "" <IP>
    smbclient -U <HOST> -L <IP>
    /usr/bin/smbclient \\\\<IP>\\share <HOST>  
    smbmap -H 127.0.0.1 -u username -p password   	
	
**Port 2049: NFS**  
	[Pentesting NFS](https://book.hacktricks.xyz/pentesting/nfs-service-pentesting)  
	[No root squash](http://fullyautolinux.blogspot.com/2015/11/nfs-norootsquash-and-suid-basic-nfs.html)
	
    showmount -e 127.0.0.1
    mkdir /mnt/share   
    sudo mount -t nfs -o v2 127.0.0.1/share /mnt/share -o nolock 
	

