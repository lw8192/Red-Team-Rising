# OSINT   
## Tools 
[OSINT Tools](https://www.osinttechniques.com/osint-tools.html)  <- List of OSINT tools for any occassion   
[The Harvester](https://github.com/laramies/theharvester)    <- gathers emails, names, subdomains, IPs and URLs      
[Recon-ng](https://github.com/lanmaster53/recon-ng)  <- Recon framework
[hunter.io](https://hunter.io/)       <- find email addresses for a company       

## DNS Look Up   
whois, nslookup, dig, host <-manual tools   
Dierce, DNSenum, DNSrecon <-automated tools  
[DNSDumpster](https://dnsdumpster.com/) <- online tool

    #Record types: MX - mail server, TXT - text, AXFR - zone transfer   
    
    nslookup -type=any <DOMAIN>          
    whois <DOMAIN>     
    host -t axfr -l <DOMAIN> <DNSSERVER>   
    dig -t axfr #zone transfer    
    dig -t mx <DOMAIN>  
    dig -t any <DOMAIN>   
    nmap --script dns-brute site.net      #brute force      
    dnsrecon.py -d site.net      
    dnsrecon.py -d site.net -t brt -D /opt/dnsrecon/namelist.txt    
