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
Metasploit: post/multi/gather/firefox_creds    
~/.mozilla/firefox   
check profiles.ini for profile names   
then go to the profile name folder   
places.sqlite      #history, bookmarks, downloads   
bookmarkbackups     #bookmarks   
logins.json         #saved logins (passwords are encrypted)      
signons.sqlite      #also saved logins    

    #download file then examine using the below command   
    cat logins.json | python -m json.tool > formatted.json  
download places.sqlite and open with [sqlitebrowser](https://www.kali.org/tools/sqlitebrowser/). Check tables: moz_origins, moz_places    
[Tool to decrypt Firefox and Thunderbird Creds](https://github.com/unode/firefox_decrypt)   
[Dumpzilla Tool](https://github.com/Busindre/dumpzilla)     

Thunderbird     
Metasploit: post/multi/gather/thunderbird_creds    
Folder: /home/[username]/.thunderbird/$PROFILE.default/    
global-messages.db.sqlite    #look at tables contacts, identities, messages, messagesText_content    
