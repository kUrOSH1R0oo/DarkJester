"""
Disclaimer: DarkJester is intended solely for ethical and legitimate uses. We are not responsible for any malicious activities or unlawful actions that occur as a result of using DarkJester. It is your responsibility to ensure that the tool is used in compliance with all applicable laws and regulations. Misuse of DarkJester for harmful, illegal, or unauthorized purposes is strictly prohibited and will be at your own risk.
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
        decrypted_file_path = encrypted_file_path.rsplit('.mime', 1)[0]
        with open(decrypted_file_path, 'wb') as dec_file:
            dec_file.write(decrypted_data)
        os.remove(encrypted_file_path)
    except Exception as e:
        print(f"[-] Error decrypting {encrypted_file_path}: {e}")

def decrypt_directory(directory_path, key):
    for root, _, files in os.walk(directory_path):
        for file_name in files:
            if file_name.endswith('.mime'):
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

