# Enumeration Quick Reference   

## Contents 
- [Enumeration Quick Reference](#enumeration-quick-reference)
  * [Contents](#contents)
  * [Checklist](#checklist)
  * [Recon](#recon)
    + [OSINT](#osint)
    + [DNS Look Up](#dns-look-up)
  * [Network Enum:](#network-enum-)
    + [NetDiscover (ARP Scanning):](#netdiscover--arp-scanning--)
  * [Host enum](#host-enum)
  * [Service Enum](#service-enum)
    + [TCP Port 21: FTP](#port-21--ftp)
    + [TCP Port 25: SMTP](#tcp-port-25--smtp)
    + [TCP Port 88: Kerberos](#tcp-port-88--kerberos)
    + [TCP Port 389: LDAP](#tcp-port-389--ldap)
    + [TCP Port 445: SMB](#tcp-port-445--smb)
    + [TCP Port 2049: NFS](#tcp-port-2049--nfs)
    + [TCP Port 3306: MySQL](#tcp-port-3306--mysql)
    + [UDP Port 161: SNMP](#udp-port-161--snmp)
  * [Resources](#resources)


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
[DNSDumpster](https://dnsdumpster.com/) <- online tool

    #Record types: MX - mail server, TXT - text, A 
    
    nslookup -type=any <DOMAIN>          
    whois <DOMAIN>     
    host -t axfr -l <DOMAIN> <DNSSERVER>   
    dig -t mx <DOMAIN>  
    dig -t any <DOMAIN>
    
## Network Enum:  
    for x in {1..254};do (ping -c 1 l.l.l.$x | grep "bytes from" &); done | cut -d " "     
    nmap -v -s 192.168.0.0/24   
    nmap -Pn -vv -F -sSU -T4 -oG /kali/192.168.15.200-254.xml 192.168.15.200-254 | grep -v 'filtered|closed' > /kali/quick_recon.txt         

### NetDiscover (ARP Scanning):

    netdiscover -i eth0
    netdiscover -r 172.21.10.0/24

## Host enum 
**Identify os, services/ports/versions. Save results to text files. **   

    autorecon 127.0.0.1 --only-scans-dir -v      
    nmap -A -sV -T 4 -vv 127.0.0.1    
    nmap -sV -sT -p- --min-rate 200 -vv 127.0.0.1     
    
    OSCP common scan types: -A, -sU, -sS, sV, -sC, -O
    debug: -vv, -d, --reason

    nc -nvzw1 192.168.53.120 1-65535 2>&1 | grep open       

More scan types: 

    -T0 or T1 (evade IDS or firewall detection)  
    -sN (TCP NULL scan - no response if open or blocked by firewall)  
    -sF (TCP FIN scan - no response if open or blocked by firewall)
    -sX (TCP XMAS scan - FINE/PSH/URG - no response if open or blocked by firewall)
    
    -sA (TCP ACK scan - see what ports are not filtered by a firewall) 
    -sW (TCP Window / ACK scan - what ports are not filtered 
    --scanflags (custom scan)
  
    -S <spoof ip>, --spoof-mac <spoof MAC>
    -D <decoy ip>, <own ip> 
    -sI <Zombie ip>  
    --traceroute 

## Service Enum   

nmap scripts: /usr/share/nmap/scripts, -sC, -sV 
	
    nmap --script <name>    --script-help 
    -sV --version-intensity
	
### TCP Port 21: FTP 
	
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
	
### TCP Port 25: SMTP
	
	smtp-user-enum -M VRF -u <user.txt> -t 127.0.0.1   
	nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 127.0.0.1  

### TCP Port 88: Kerberos
see active directory cheatsheet
	
### TCP Port 389: LDAP 
see Active Directory Cheat Sheet 
	
### TCP Port 445: SMB 
	
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
	
    smbclient -L 10.10.10.3 --option='client min protocol=NT1'
	
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


### TCP Port 2049: NFS 
	
[Pentesting NFS](https://book.hacktricks.xyz/pentesting/nfs-service-pentesting)  
[No root squash](http://fullyautolinux.blogspot.com/2015/11/nfs-norootsquash-and-suid-basic-nfs.html)
	
    showmount -e 127.0.0.1
    mkdir /mnt/share   
    sudo mount -t nfs -o v2 127.0.0.1/share /mnt/share -o nolock 
	
### TCP Port 3306: MySQL
	
	mysql -h 10.10.10.10 -u root -p   
	
### UDP Port 161: SNMP 
	
SNMP Walk: 

    snmpwalk -c public -v1 ipaddress 1
    snmpwalk -c private -v1 ipaddress 1
    snmpwalk -c manager -v1 ipaddress 1

Nmap: 

    nmap 172.21.0.0 -Pn -sU -p 161 --script=

	/usr/share/nmap/scripts/snmp-brute.nse
	/usr/share/nmap/scripts/snmp-hh3c-logins.nse
	/usr/share/nmap/scripts/snmp-info.nse
	/usr/share/nmap/scripts/snmp-interfaces.nse
	/usr/share/nmap/scripts/snmp-ios-config.nse
	/usr/share/nmap/scripts/snmp-netstat.nse
	/usr/share/nmap/scripts/snmp-processes.nse
	/usr/share/nmap/scripts/snmp-sysdescr.nse
	/usr/share/nmap/scripts/snmp-win32-services.nse
	/usr/share/nmap/scripts/snmp-win32-shares.nse
	/usr/share/nmap/scripts/snmp-win32-software.nse
	/usr/share/nmap/scripts/snmp-win32-users.nse

Metasploit aux modules: 

 	auxiliary/scanner/misc/oki_scanner                                    
 	auxiliary/scanner/snmp/aix_version                                   
 	auxiliary/scanner/snmp/arris_dg950                                   
 	auxiliary/scanner/snmp/brocade_enumhash                               
 	auxiliary/scanner/snmp/cisco_config_tftp                               
 	auxiliary/scanner/snmp/cisco_upload_file                              
 	auxiliary/scanner/snmp/cnpilot_r_snmp_loot                             
 	auxiliary/scanner/snmp/epmp1000_snmp_loot                             
 	auxiliary/scanner/snmp/netopia_enum                                    
 	auxiliary/scanner/snmp/sbg6580_enum                                 
 	auxiliary/scanner/snmp/snmp_enum                                 
 	auxiliary/scanner/snmp/snmp_enum_hp_laserjet                           
 	auxiliary/scanner/snmp/snmp_enumshares                                
 	auxiliary/scanner/snmp/snmp_enumusers                                 
 	auxiliary/scanner/snmp/snmp_login                                     


Onesixtyone: 

	onesixtyone -c /usr/share/doc/onesixtyone/dict.txt 172.21.0.X

Snmp-check


	snmp-check 172.21.0.0 -c public


Impacket: 

	python3 samdump.py SNMP 172.21.0.0
	
	
## Resources  
http://www.0daysecurity.com/penetration-testing/enumeration.html
Backup Link: https://web.archive.org/web/20201122081447/http://www.0daysecurity.com/penetration-testing/enumeration.html
