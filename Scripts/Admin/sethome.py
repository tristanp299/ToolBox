#!/bin/env python3
import os,sys
from subprocess import run
with open("/home/kali/.zshrc",'r') as f:
	file = f.readlines()
with open("/home/kali/.zshrc",'w') as f:
	for line in file:
		if "export HOME=" in line:
			line = f'export HOME="{sys.argv[1]}"'
			print(f'Line replaced with: {line}')
		f.write(line)
