# Linux Forensics    
For most Linux distros (Debian, Ubuntu etc)    
## Linux Logs
Logs: /var/log     
log config: /etc/syslog.conf, /etc/rsyslog.conf     

Can clean plaintext logs, not binary (usually).          

/var/log/btmp: failed logins    
/var/log/wtmp: historical data of logins    
btmp and wtmp are both binary logs, read using last    

every user that logins in on Linux host - logs in auth log    
/var/log/auth.log    

Syslog: messages recorded by host about system activity, different logging levels.    
/var/log/syslog   

## Command History    
sudo commands - stored in auth log     

    cat/var/log/auth.log* |grep-i COMMAND | tail   

any commands other then sudo - stored in user's bash history in home dir      
Vim text editor - stores logs for opened files in vim in ~/.viminfo      

.bashrc file that runs when bash shell is spawned     
Systemwide settings
/etc/bash.bashrc     
/etc/profile    

## Timestomping     
Changing timestamps of files on Linux to blend in.    
Mtime - last data modification.    
Atime - last data access.   
Ctime - last file status change.     
Use touch to change the modify or access time.     
Better: change system time, 'touch' the file, then change the system time back to change the ctime.    
https://www.inversecos.com/2022/08/detecting-linux-anti-forensics.html     

## Browser Forensics   
### Firefox   
~/.mozilla/firefox   
check profiles.ini for profile names   
then go to the profile name folder   
places.sqlite      #history, bookmarks, downloads   
bookmarkbackups     #bookmarks   
download places.sqlite and openw ith sqlitebrowser. Check tables: moz_origins, moz_places    
