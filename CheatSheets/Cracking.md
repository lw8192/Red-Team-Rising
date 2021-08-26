# Cracking Resources 
## References 
[Cracking the Hashes](https://zweilosec.gitbook.io/hackers-rest/os-agnostic/password-cracking/cracking-the-hashes)   

## Tools
Passwords, login pages, etc.
[Ciphey](https://github.com/Ciphey/Ciphey)  
[CyberChef](https://gchq.github.io/CyberChef/)  

## Wordlists   
[Seclists](https://github.com/danielmiessler/SecLists)   
[Have I Been Pwned Passwords](https://haveibeenpwned.com/Passwords)   
[Rainbow Crack, Rainbow Tables](http://project-rainbowcrack.com/table.htm)   
[Rocktastic Mega Wordlist](https://labs.nettitude.com/tools/rocktastic/)  
[berzerk0 wordlist](https://www.hack3r.com/forum-topic/wikipedia-wordlist)   
[Weakpass](https://www.hack3r.com/forum-topic/wikipedia-wordlist)   
Make your own wordlist: [Crunch](https://sourceforge.net/projects/crunch-wordlist/)  [Cewl](https://github.com/digininja/cewl)  

# Cracking Services   

### Hydra
ftp, ssh, http-post, http-get 

    hydra -e nsr -l username -P wordlist 10.10.10.10 service   
    -e nsr: tries no pass, same pass as usernames, passwords as backwords username  
    hydra -L user.txt -P wordlist.txt 10.10.10.10 http-get /directory  
    
### Crowbar 
rdp  

### Misc Crackers  
wpscan: crack wordpress logins 

# Cracking Offline Passwords  
[Crackstation](https://crackstation.net/): try first esp. with NTLM / Windows hashes      
[Name That Hash](https://nth.skerritt.blog/)   
[Search that Hash](https://github.com/HashPals/Search-That-Hash) , [Colab STH](https://github.com/vaishnavpardhi/colabsth/)  
 
    hash-identifier [hash]     

### John 
    john --wordlist=/usr/share/wordlists/rockyou.txt shadow 
    
    

### Hashcat  
[One rule to rule them all](https://github.com/NotSoSecure/password_cracking_rules)  

    hashcat -m [mode] hashes wordlist    

Large wordlist - use google colab projects: [colabcat](https://github.com/someshkar/colabcat) or [colabsth](https://github.com/vaishnavpardhi/colabsth/) 
