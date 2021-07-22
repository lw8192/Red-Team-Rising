  
# Enum  
## Quick Enum
    hostname; ip addr; netstat -antp; arp -a   
    whoami; id   
    uname -r   
    cat /etc/passwd | grep /bin/bash   
    ls -l /etc/shadow   
    sudo -l  
## Scripts
    run lse.sh, linpeas.sh 
## Checklists
[Linux Priv Esc Checklist](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)    
  
# Exploits
## Cronjobs    
    cat /etc/cronjobs   
    crontab -l    
## SUID Binaries
    find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \;  2>/dev/null               
    ps aux | grep “^root”                   
   

# File Transfer 
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null 


# Resources
## Cheat Sheets
## Learn More
