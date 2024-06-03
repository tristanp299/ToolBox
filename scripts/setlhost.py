#!/bin/env python3
import os,sys
with open("/home/kali/.kali",'r') as f:
	file = f.readlines()
with open("/home/kali/.kali",'w') as f:
	c = 0
	for line in file:
		if "export LHOST=" in line and c == 0:
			line = f'export LHOST="{sys.argv[1]}"\n'
			print(f'Line replaced with: {line}')
			c+=1
		f.write(line)
