import socks
import socket
import requests
import stem.process
from stem import Signal
from stem.control import Controller
import nmap

def scan_ports(ip, ports):
    nm = nmap.PortScanner()
    scanned = nm.scan(hosts=ip, arguments='-p {}'.format(','.join([str(port) for port in ports]))
    return scanned['scan'][ip]['tcp'].items()

# start a tor instance in a separate thread and set the port to 9050 (default)
tor_process = stem.process.launch_tor_with_config(
    config={
        'SocksPort': str(9050), # change this if you've changed the default Tor SOCKS port
        'ControlPort': str(9051),  # change this if you've changed the default Tor control port
        'ExitNodes': '{europe}',   # use European exit nodes to reduce detection probability
    },
    init_msg_handler=None,
    timeout=30)

# connect to tor via controller
controller = Controller.from_port(port=9051)  
controller.authenticate()
controller.signal(Signal.NEWNYM)

# set the socks proxy for requests library
socks.set_default_proxy(socks.SOCKS5, 'localhost', 9050)
socket.socket = socks.socksocket

# send your request through Tor
response = requests.get('https://www.example.com')

print(response.status_code) # should be 200 if the request was successful

# terminate tor process
tor_process.terminate()

'''
>>> scan_ports('8.8.8.8', [21, 22, 23]) # Scan ports 21, 22 and 23 on IP address 8.8.8.8
[(21, {'state': 'open', 'reason': 'syn-ack', 'name': 'ftp', 'product': '', 'version': '', 'extrainfo': '', 'cpe': ''}), (22, {'state': 'filtered', 'reason': 'no-response', 'name': 'ssh', 'product': '', 'version': '', 'extrainfo': '', 'cpe': ''})]
'''

'''## Half-open port scanning
import os
from scapy.all import *

# set the target IP address
target_ip = "192.168.1.1"

# define a function to send a SYN packet and check if it's open or closed
def is_port_open(port):
    src_port = RandShort()
    pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=int(port), flags="S", seq=RandShort())
    response = sr1(pkt, timeout=2)
    if response[TCP].flags == 0x12: # SYN+ACK
        return True
    elif response.haslayer(ICMP): # ICMP error
        if int(response[ICMP].type) == 3 and int(response[ICMP].code) in [1,2,3,9,10,13]:
            return False
    else:
        return False

# get the open ports using half-open scanning
ports = []
for port in range(1, 65535):
    if is_port_open(port) == True:
        print("Port {} is open".format(port))
        ports.append(port)
'''