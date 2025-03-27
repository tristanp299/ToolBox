#!/bin/env python3
import os,sys
from subprocess import run, Popen, PIPE
folder = sys.argv[1]
#Create backup
run(f'tar -cvzf {folder}.bak.tgz {folder}'.split())

#change files from .txt to .md

for path, dir, file in os.walk(os.path.join(folder)):
	for f in file:
		if '.txt' in f:
			new_file = f.replace('.txt','.md')
			new_file = os.path.join(path,new_file)
			old_file = os.path.join(path,f)
			run(f'mv {old_file} {new_file}'.split())
			
		elif '.md' in f:
			continue
		else:
			old_file = os.path.join(path,f)
			if ' ' in old_file:
				old_file = "'"+old_file+"'"
			f = f.split(' ')
			f = '_'.join(f)
			new_file = f+'.md'
			print(new_file)
			new_file = os.path.join(path,new_file)
			command = f'mv ./{old_file} ./{new_file}'
			print(command)
			p = Popen(f'mv ./{old_file} ./{new_file}'.split())
			out,err = p.communicate()
			
		
			
			
