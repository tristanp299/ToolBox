# Custom Hashcat Module for Apache Shiro 1 SHA-512
- by Dylan Evans at Maveris Labs
https://medium.com/maverislabs/crack-faster-hack-smarter-c0c4defbcae7
### Scenario
Identified a server running Nexus Repository 3 that was vulnerable to CVE-2024–4956

Ultimately extracting Apache Shiro 1 SHA-512 password hashes
### Objective
Wanting to increase cracking performance by taking advantage of a multiple GPU hash cracking rig as well as Hashcat features such as advanced rule support, this led to the journey of creating a custom Hashcat module for the Apache Shiro 1 hashing implementation.
### Notes
	- note that the Apache Shiro 1 SHA-512 algorithm is used by Sonatype Repository 3
- Downloading public Github repo and examine code.
- Recursive **grep** command for the text “**shiro.crypto**”, to reveal hashing class functions.

![[Pasted image 20240915141511.png]]

- Do research to see if the the tool or module is already available
	- *No need to re-invent the wheel*
	
- 2024 - hashcat has guide on creating custom modules
- Need to use hashcat module & create OpenCL Kernel
-
https://github.com/hashcat/hashcat/blob/master/docs/hashcat-plugin-development-guide.md#kernel-slow-hash-type

- **What is OpenCL?**
- OpenCL is a framework for writing programs that execute across heterogeneous platforms, including CPUs, GPUs, and other processors.
	- **C-like Syntax**

Kernel Development:
https://github.com/fin3ss3g0d/Shiro1Tools/blob/main/shiro-crack/shiro1.c

- Use a pre-existing Hashcat helper file for SHA-512 (**inc_hash_sha512.cl**)

- Make sure to TEST!
### Hashcat Test Suite
https://github.com/hashcat/hashcat/blob/master/docs/hashcat-plugin-development-guide.md#test-suite
- Written in Perl
### Takeaways

- The Apache Shiro 1 SHA-512 hashing algorithm used to have a limited attack surface due to the lack of Hashcat support or similar project that can utilize GPU hardware to crack the algorithm; this is no longer true.

- Sonatype’s default iteration count is relatively low at 1024 iterations per hash and is actually below the Apache Shiro default iteration, making it a fairly inexpensive algorithm with decent cracking times.

- Sonatype hashes user credentials for the web application database using this algorithm, if a system is vulnerable to a LFI/path traversal (i.e. CVE-2024–4956) vulnerability, you can extract these hashes from OrientDB **.pcl** files and then crack them with the Hashcat module. Any other means of gaining access to these files is valid such as compromising a system where these files have been backed up, compromising a system through a different vulnerability, etc.

- We learned how to create a moderately complex Hashcat module as well as where to find the official documentation for plugin development that can be applied to different algorithms if we come across a situation such as this in the future. We also learned how to test our module to make sure it is working correctly.