#!/bin/bash 
#run script as sudo in new Kali to download tools needed 
wget -O https://raw.githubusercontent.com/Dewalt-arch/pimpmykali/blob/master/pimpmykali.sh |bash
apt-get install feroxbuster sshuttle chisel 
python3 -m pip install pipx
pipx ensurepath
pipx install crackmapexec

#download shells
mkdir /home/kali/shells
wget https://raw.githubusercontent.com/flozz/p0wny-shell/blob/master/shell.php -o /home/kali/shells/p0wneyWebshell.php 

#download scripts
mkdir /home/kali/PEScripts/Linux 
wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh -o /home/kali/PEScripts/Linux/linpeas.sh
wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh -o /home/kali/PEScripts/Linux/lse.sh 
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -o /home/kali/PEScripts/Linux/LinEnum.sh
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -o /home/kali/PEScripts/Linux/les.sh

mkdir /home/kali/PEScripts/Windows 
wget https://raw.githubusercontent.com/bitsadmin/wesng/master/wes.py -o /home/kali/PEScripts/Windows/wes.py 
wget https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1 -o /home/kali/PEScripts/Windows/PowerUp.ps1


#download binaries 
mkdir /home/kali/bins 
