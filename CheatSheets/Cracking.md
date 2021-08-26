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

### Misc Service Crackers  
wpscan: crack wordpress logins 
[pwn Jenkins](https://github.com/Scr1ptK1ddie/pwn_jenkins): crack Jenkins service  


# Cracking Offline Passwords  
[Crackstation](https://crackstation.net/): try first esp. with NTLM / Windows hashes      
[Name That Hash](https://nth.skerritt.blog/)   
[Search that Hash](https://github.com/HashPals/Search-That-Hash)
 
    hash-identifier [hash]     


Large wordlist - use google colab projects: [colabcat](https://github.com/someshkar/colabcat) or [colabsth](https://github.com/vaishnavpardhi/colabsth/) 
 
 
## Hashcat 
[One rule to rule them all](https://github.com/NotSoSecure/password_cracking_rules)  

    hashcat -m [mode] hashes wordlist   
### Benchmark Test (HASH Type)

    hashcat -b -m #type
### Show Example Hash 

    hashcat -m #type --example-hashes
### DICTIONARY ATTACK

    hashcat -a 0 -m #type hash.txt dict.txt

DICTIONARY + RULES ATTACK

    hashcat -a 0 -m #type hash.txt wordlist.txt -r rule.txt  
    
    
COMBINATION ATTACK

    hashcat -a 1 -m #type hash.txt wordlist1.txt wordlist2.txt 
   
   

### Mask Attack

   hashcat -a 3 -m #type hash.txt ?a?a?a?a?a?a

HYBRID DICTIONARY + MASK

   hashcat -a 6 -m #type hash.txt wordlist.txt ?a?a?a?a

HYBRID MASK + DICTIONARY

   hashcat -a 7 -m #type hash.txt ?a?a?a?a wordlist.txt  
   

### Increment

Default Increment

    hashcat -a 3 -m #type hash.txt ?a?a?a?a?a --increment

Increment Minimum Length

    hashcat -a 3 -m #type hash.txt ?a?a?a?a?a --increment-min=4

Increment Max Lenth
    hashcat -a 3 -m #type hash.txt ?a?a?a?a?a?a --increment-max=5

Session Restore 
    hashcat -a 0 -m #type --restore --session <uniq_name> hash.txt wordlist.txt


### Cracking krb5ts Keys

    hashcat -m 13100 --force <TGSs_file> <passwords_file>

### Cracking Asrep keys

    hashcat -a 0 -m 18200 <asrep_file> <password_file> 

    
    

## John   
 

