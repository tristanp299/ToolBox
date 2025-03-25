#!/bin/env python3
import os,sys
with open("/home/kali/.kali",'r') as f:
	file = f.readlines()
with open("/home/kali/.kali",'w') as f:
	for line in file:
		if "export RHOST=" in line:
			line = f'export RHOST="{sys.argv[1]}"\n'
			print(f'Line replaced with: {line}')
		f.write(line)
