#!/bin/env python3
import netifaces as ni
import time



try:
	ip = ni.ifaddresses('tun0')[ni.AF_INET][0]['addr']
	print('VPN -> '+ip)
except ValueError as VE:
	print('VPN not connected')
		
