#!/bin/env python3
import sys

with open (sys.argv[1],'r') as f:
	data = [i for i in f.readlines()]
	
flag = False	
new_file = []
for c, line in enumerate(data):
	new_line = line.split(':')[1:]
	new_line = ':'.join(new_line)
	new_line = "'"+new_line.strip()+"'\n"
	line = line[:line.find(':')]+':'+new_line
	new_file.append(line)
	
with open (sys.argv[1],'w') as f:
	for line in new_file:
		f.write(line)
	
