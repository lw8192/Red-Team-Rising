#!/bin/bash 
#run script as sudo in new Kali to download tools needed 
apt-get update && apt-get upgrade
apt-get install python3
apt-get install pip3

#download pimpmykali - impacket, seclists, etc
wget https://raw.githubusercontent.com/Dewalt-arch/pimpmykali/master/pimpmykali.sh |bash    

#download search that hash 
python3 -m pip install pipx
pip install search-that-hash  

#download web tools 
apt-get install feroxbuster sshuttle chisel gobuster nikto  

#download compiler tools 
apt-get install gcc-multilib mingw-w64
pipx ensurepath
pipx install crackmapexec  

#download foxy proxy, user agent switcer and wapp analyzer 
wget https://addons.mozilla.org/firefox/downloads/file/3616824/foxyproxy_standard-7.5.1-an+fx.xpi -o /tmp/foxyproxy_standard-7.5.1-an+fx.xpi
firefox /tmp/foxyproxy_standard-7.5.1-an+fx.xpi
wget https://addons.mozilla.org/firefox/downloads/file/4098688/user_agent_string_switcher-0.5.0.xpi -o /tmp/user_agent_string_switcher-0.5.0.xpi
firefox /tmp/user_agent_string_switcher-0.5.0.xpi 
wget https://addons.mozilla.org/firefox/downloads/file/4095500/wappalyzer-6.10.62.xpi -o /tmp/wappalyzer-6.10.62.xpi 
firefox /tmp/wappalyzer-6.10.62.xpi 

#download shells
mkdir ~/shells
wget https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php -o ~/shells/p0wneyWebshell.php 
wget https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php -o ~/shells/wwwWebshell.php

#download scripts
mkdir ~/PEScripts
mkdir ~/PEScripts/Linux 
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh -o /home/kali/PEScripts/Linux/lse.sh 
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -o /home/kali/PEScripts/Linux/LinEnum.sh
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -o /home/kali/PEScripts/Linux/les.sh
wget https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py -o /home/kali/PEScripts/Linux/linuxprivchecker.py
wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl -o /home/kali/PEScripts/Linux/linux-exploit-suggester-2.pl

mkdir ~/PEScripts/Windows 
wget https://raw.githubusercontent.com/bitsadmin/wesng/master/wes.py -o /home/kali/PEScripts/Windows/wes.py 
wget https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1 -o /home/kali/PEScripts/Windows/PowerUp.ps1

