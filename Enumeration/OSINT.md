# OSINT   
## Tools 
[OSINT Tools](https://www.osinttechniques.com/osint-tools.html)  <- List of OSINT tools for any occassion   
[The Harvester](https://github.com/laramies/theharvester)    <- gathers emails, names, subdomains, IPs and URLs      
[Recon-ng](https://github.com/lanmaster53/recon-ng)  <- Recon framework   
Shodan <- Banners and scanning    
Spiderfoot <- Give scan name and seed target (domain name, host name, email) to collect data. Free and paid versions.   
[hunter.io](https://hunter.io/)       <- find email addresses for a company     


## DNS Look Up   
whois, nslookup, dig, host <-manual tools   
Dierce, DNSenum, DNSrecon <-automated tools  
[DNSDumpster](https://dnsdumpster.com/) <- online tool   
Dump DNS records to figure out what is accessible using a zone transfer.    

    #Record types: MX - mail server, TXT - text, AXFR - zone transfer   
    
    nslookup -type=any <DOMAIN>          
    whois <DOMAIN>      #id auth server  
    host -t axfr -l <DOMAIN> <DNSSERVER>   
    dig -t axfr #zone transfer    
    dig -t mx <DOMAIN>  
    dig -t any <DOMAIN>     
    nmap --script dns-brute site.net -sS -p 53      #brute force      
    dnsrecon.py -d site.net      
    dnsrecon.py -d site.net -t brt -D /opt/dnsrecon/namelist.txt    

## Breached Data   
HaveIBeenPwned.com    
Usually you can't use breached data on a pen test - makes sure to confirm with legal!   

## Site Enum   
Info gathering: https://www.sec.gov/edgar/search-and-access, job networking sites, xxlek.com, namechk.com, whatsmyname.app     
Sites to use: shodan.io, network-tools.com, viewdns.info, securityspace.com    
Crawl site for a WordList:     

    cewl -m 8 -w out_list.txt -a --meta-file list-meta.txt -e --email_file list_email.txt https://site.com/
### Google Dorks  
Google Hacking db: collect of dorks. FGDS (Fast Google Dorks Scan) can automate but also get you banned.    

    site:site.com     intext:@site.com      #id emails for domain    
    filetype:pdf "password"      "policy"site:site.org        #search PDFs for keywords and policy for domain    
    "index of /" backup.ab       #id dir lists where backup.ab is (Android device backup)     
    filetype:rd        #id rdp connection profiles    
    link:www.[site].com     
