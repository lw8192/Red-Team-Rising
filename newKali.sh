#!/bin/bash 
#run script as sudo in new Kali to download tools needed 
apt-get update && apt-get upgrade

#download pimpmykali - impacket, seclists, etc
wget https://raw.githubusercontent.com/Dewalt-arch/pimpmykali/blob/master/pimpmykali.sh |bash    

#download search that hash 
python3 -m pip install pipx
pip install search-that-hash  

#download web tools 
apt-get install feroxbuster sshuttle chisel gobuster nikto  

#dowload compiler tools 
apt-get install gcc-multilib mingw-w64
pipx ensurepath
pipx install crackmapexec  

#download foxy proxy, user agent switcer and wapp analyzer 
wget https://addons.mozilla.org/firefox/downloads/file/3616824/foxyproxy_standard-7.5.1-an+fx.xpi
firefox ./foxyproxy_standard-7.5.1-an+fx.xpi
wget https://addons.mozilla.org/firefox/downloads/file/3769639/user_agent_switcher_and_manager-0.4.7.1-an+fx.xpi
firefox ./user_agent_switcher_and_manager-0.4.7.1-an+fx.xpi  
wget https://addons.mozilla.org/firefox/downloads/file/3819588/wappalyzer-6.7.13-fx.xpi 
firefox wappalyzer-6.7.13-fx.xpi 

#download shells
mkdir /home/kali/shells
wget https://raw.githubusercontent.com/flozz/p0wny-shell/blob/master/shell.php -o /home/kali/shells/p0wneyWebshell.php 
wget https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php -o /home/kali/shells/wwwWebshell.php

#download scripts
mkdir /home/kali/PEScripts/Linux 
wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh -o /home/kali/PEScripts/Linux/linpeas.sh
wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh -o /home/kali/PEScripts/Linux/lse.sh 
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -o /home/kali/PEScripts/Linux/LinEnum.sh
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -o /home/kali/PEScripts/Linux/les.sh
wget https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py -o /home/kali/PEScripts/Linux/linuxprivchecker.py
wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl -o /home/kali/PEScripts/Linux/linux-exploit-suggester-2.pl

mkdir /home/kali/PEScripts/Windows 
wget https://raw.githubusercontent.com/bitsadmin/wesng/master/wes.py -o /home/kali/PEScripts/Windows/wes.py 
wget https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1 -o /home/kali/PEScripts/Windows/PowerUp.ps1


#download binaries 
mkdir /home/kali/bins 
