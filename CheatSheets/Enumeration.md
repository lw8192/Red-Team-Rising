# Enumeration Quick Reference   

## Contents 
- [Enumeration Quick Reference](#enumeration-quick-reference)
  * [Checklist](#checklist)
  * [Recon](#recon)
    + [OSINT](#osint)
    + [DNS Look Up](#dns-look-up)
  * [Network Enum:](#network-enum-)
  * [Host enum](#host-enum)
  * [Service Enum](#service-enum)
    + [Port 21: FTP](#port-21--ftp)
    + [Port 25: SMTP](#port-25--smtp)
    + [Port 389: LDAP](#port-389--ldap)
    + [Port 139, 445: SMB](#port-139--445--smb)
    + [Port 2049: NFS](#port-2049--nfs)


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
- [ ] Service specific exploits 
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
    whois <DOMAIN> 
    host -t axfr -l <DOMAIN> <DNSSERVER>   
    dig -t mx <DOMAIN>  
    dig -t any <DOMAIN>
    
## Network Enum:  
    for x in {1 .. 254};do (ping -c 1 l.l.l.$x | grep "bytes from" &); done | cut -d " "     
    nmap -v -s 192.168.0.0/24   
    nmap -Pn -vv -F -sSU -T4 -oG /kali/192.168.15.200-254.xml 192.168.15.200-254 | grep -v 'filtered|closed' > /kali/quick_recon.txt         

### NetDiscover (ARP Scanning):

    netdiscover -i eth0
    netdiscover -r 172.21.10.0/24

## Host enum 
**Identify os, services/ports/versions. Save results to text files. **   

    autorecon 127.0.0.1 --only-scans-dir -v      
    nmap -A -T 4 -vv 127.0.0.1    
    nmap -sV -p- --min-rate 200 -vv 127.0.0.1     

    nc -nvzw1 192.168.53.120 1-65535 2>&1 | grep open       

## Service Enum   

nmap scripts: /usr/share/nmap/scripts   
nmap --script <name>    --script-help 
	
### Port 21: FTP 
	
[Enumerating ftp](https://book.hacktricks.xyz/pentesting/pentesting-ftp)   
Can I ...
- [ ] Anonymously log in or use known creds?  
- [ ] See hidden files? 
- [ ] Download important files (ie. backup files, ssh priv keys, etc)?
- [ ] Upload a webshell?   
- [ ] Find FTP exploits on searchsploit / Google? 
- [ ] Crack creds with hydra? 
	
	anon log in: ftp / no password	or 	Anonymous: asdfasdf           
	nmap -sV -Pn -vv -p 21 --script=ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221     
    hydra -C ftp/usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -u 127.0.0.1 ftp    
	
### Port 25: SMTP
	
	smtp-user-enum -M VRF -u <user.txt> -t 127.0.0.1   
	nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 127.0.0.1  
	
### Port 389: LDAP 
	
	ldapsearch -h 127.0.0.1 -p 389 -x -s base
	
### Port 139, 445: SMB 
	
Can I...
Enum with smbmap, enum4linux, nmap, crackmapexec, check for anon log in
[Eternal Blue](https://github.com/3ndG4me/AutoBlue-MS17-010) 
[enum4linux-ng](https://github.com/cddmp/enum4linux-ng)    
	
    SAMBA 3.x-4.x #  vulnerable to linux/samba/is_known_pipename
    SAMBA 3.5.11 # vulnerable to linux/samba/is_known_pipename

Access with smbclient or rpcclient
	
    smbclient -L 10.10.10.10  
    smbclient -U <HOST> -L 10.10.10.10
    smbclient \\\\10.10.10.10\\share  

if getting error "protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED or box in running SMB1	
    smbclient -L //10.10.10.3/ --option='client min protocol=NT1'
	
smbmap: 
	
    smbmap -H 127.0.0.1 -d domain -u username -p password   	

enum4linux: 
	
    enum4linux -a 172.21.0.0
	
nmap: 
	
    nmap --script smb-* -p 139,445, 172.21.0.0
    nmap --script smb-enum-* -p 139,445, 172.21.0.0


CrackMapExec: 

    crackmapexec smb -L 
    crackmapexec 172.21.0.0 -u Administrator -H [hash] --local-auth
    crackmapexec 172.21.0.0 -u Administrator -H [hash] --share
    crackmapexec smb 172.21.0.0/24 -u user -p 'Password' --local-auth -M mimikatz

Impacket SmbClient: 

     /usr/share/doc/python3-impacket/examples/smbclient.py username@172.21.0.0
	
Impacket: 

     python3 samdump.py SMB 172.21.0.0


### Port 2049: NFS 
	
[Pentesting NFS](https://book.hacktricks.xyz/pentesting/nfs-service-pentesting)  
[No root squash](http://fullyautolinux.blogspot.com/2015/11/nfs-norootsquash-and-suid-basic-nfs.html)
	
    showmount -e 127.0.0.1
    mkdir /mnt/share   
    sudo mount -t nfs -o v2 127.0.0.1/share /mnt/share -o nolock 
	
### Port 3306: MySQL
	
	mysql -h 10.10.10.10 -u root -p
