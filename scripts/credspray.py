import argparse 
alias nxc_spray='nxc smb "$1" -u "$2" -p "$3" | tee -a smb.AD.txt ; nxc smb "$1" -u "$2" -p "$3" --local-auth | tee -a smb.local.txt ; nxc wmi "$1" -u "$2" -p "$3" | tee -a wmi.AD.txt ; nxc wmi "$1" -u "$2" -p "$3" --local-auth | tee -a wmi.local.txt ; nxc rdp "$1" -u "$2" -p "$3" | tee -a rdp.AD.txt ; nxc rdp "$1" -u "$2" -p "$3" --local-auth | tee -a rdp.local.txt; nxc ftp "$1" -u "$2" -p "$3" | tee -a ftp.AD.txt ; nxc ftp "$1" -u "$2" -p "$3" --local-auth | tee -a ftp.local.txt ; nxc winrm "$1" -u "$2" -p "$3" | tee -a winrm.AD.txt ; nxc winrm "$1" -u "$2" -p "$3" --local-auth | tee -a winrm.local.txt ; nxc mssql "$1" -u "$2" -p "$3" | tee -a mssql.AD.txt ; nxc mssql "$1" -u "$2" -p "$3" --local-auth | tee -a mssql.local.txt ; nxc ldap "$1" -u "$2" -p "$3" | tee -a ldap.AD.txt ; nxc ldap "$1" -u "$2" -p "$3" --local-auth | tee -a ldap.local.txt ;'

class NXC:

    def __init__(self):
        self.username = None
        self.password = None
        self.target = None
        self.protocols = ['smb','wmi','ftp','rdp','winrm','mssql','ldap']

    def parse_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-u','--username',help='username or list')
        parser.add_argument('-p','--password',help='password or list')
        parser.add_argument('-t','--target',help='target ip or list')
        args = parser.parse_args()
        self.username = args.username
        self.password = args.password
        self.target = args.target

    
