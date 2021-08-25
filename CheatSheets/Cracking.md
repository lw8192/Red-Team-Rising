# Cracking 
## References 
[Cracking the Hashes](https://zweilosec.gitbook.io/hackers-rest/os-agnostic/password-cracking/cracking-the-hashes)   
## Tools
Passwords, login pages, etc.
[Ciphey](https://github.com/Ciphey/Ciphey)  
[CyberChef](https://gchq.github.io/CyberChef/)  
[Crackstation](https://crackstation.net/)   
Hydra
John the Ripper 
Hashcat 
## Wordlists   
[Have I Been Pwned Passwords](https://haveibeenpwned.com/Passwords)   
[Seclists](https://github.com/danielmiessler/SecLists)  

## Services   

### Hydra
ftp, ssh, http-post 
### Crowbar 
rdp  

## Offline Passwords  
[Crackstation](https://crackstation.net/): try first esp. with NTLM / Windows hashes

    hash-identifier [hash]  

### John 
    john --wordlist=/usr/share/wordlists/rockyou.txt shadow 
    
    

### Hashcat  
[One rule to rule them all](https://github.com/NotSoSecure/password_cracking_rules)  

    hashcat -m [mode] hashes wordlist    

Linux password files: Use google colab projects: [colabcat](https://github.com/someshkar/colabcat)  
