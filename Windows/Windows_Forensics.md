# Windows Forensics   
## Memory Analysis with Volatility     
Usage:   

    vol -q -f image.mem module > output.txt     
Useful Volatility modules:     

	 windows.netscan.NetScan	#netsat info    
	 windows.pstree.PsTree	#process tree info    
	 windows.pslist.PsList		#pslist    
	 windows.cmdline.CmdLine	#command line ran of process    
	 windows.filescan.FileScan	#file objects    
	 windows.dlllist.DllList		#loaded DLLs       
