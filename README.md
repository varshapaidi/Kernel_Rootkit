Kernel_Rootkit
==============

A kernel rootkit is a particular type of malware that hides its presence from the user and system administrator, by modifying the OS kernel. 

A rootkit is a kernel module---a library dynamically loaded into the kernel.

Rootkits make small changes to OS kernel data structures to hide the presence of malicious code. In our ssh example, a rootkit might hide the ssh process in the output of the ps command. 

A rootkit might also hide its binary in the file system, the open socket from netstat, or even hide its CPU usage. 


The goals of this project:

- To make the rootkit persistent.
- To hide the ssh server.
- To hide the module itself.
- To hide the open socket.
- To hide module files.
