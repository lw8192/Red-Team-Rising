# Quick Reference for Privilige Escalation   
## Linux Priv Esc   
Tools: 
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null   

Quick Initial Linux Checklist:   
hostname; ip addr; netstat -antp; arp -a   
whoami; id   
uname -r   
cat /etc/passwd | grep /bin/bash   
cat /etc/shadow   
sudo -l   
run lse.sh, linpeas.sh   

In depth manual enum:
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \;  2>/dev/null               
ps aux | grep “^root”                   
cat /etc/cronjobs   
crontab -l   

[Linux Priv Esc Checklist](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)



#Windows Priv Esc

