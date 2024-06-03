#!/bin/env python3
import os,sys
with open("/home/kali/.kali",'r') as f:
	file = f.readlines()
with open("/home/kali/.kali",'w') as f:
	for line in file:
		if "export cwd=" in line:
			cwd = os.getcwd()
			line = f'export cwd="{cwd}"\n'
			print(f'Line replaced with: {line}')
		f.write(line)
