# Windows Forensics   
## Memory Analysis with Volatility     
Run strings on a memory image:   

    strings image.mem > img.strings-asc.txt	            #ASCII strings    
    strings -e l image.mem > img.strings-unile.txt      #16 bit little endian strings   
    strings -e b image.mem > img.strings-unibe.txt      #16-bit big endian strings   

Usage:   

    vol -q -f image.mem module > output.txt   
    #then analyze text files as you normally would with a live machine (ie look at the process list)   
Useful Volatility modules:     

	 windows.netscan.NetScan	#netsat info    
	 windows.pstree.PsTree	#process tree info    
	 windows.pslist.PsList		#pslist    
	 windows.cmdline.CmdLine	#command line ran of process    
	 windows.filescan.FileScan	#file objects    
	 windows.dlllist.DllList		#loaded DLLs       
