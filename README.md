# DarkJester: Ransomware

![GIF](https://github.com/Kuraiyume/DarkJester/blob/main/Art.gif)

**DarkJester** is an advanced ransomware developed in Python, offering a wide range of capabilities that set it apart from typical ransomware. It is highly modular and adaptable, allowing seamless integration of additional features. DarkJester combines destructive ransomware tactics with advanced espionage capabilities, including file encryption, reverse shell mechanisms, and system reconnaissance.

## Features

- **AES-256 Encryption**: Utilizes AES-256 in CBC (Cipher Block Chaining) mode for robust symmetric encryption.
- **File Exfiltration**: Before encryption, victim files will be delivered through the server in original format.
- **Key and System Exfiltration**: Captures the decryption key along with detailed system information, such as OS, processor, architecture, and MAC address, and sends it to a server running.
- **Multithreaded Encryption/Decryption**: The encryption and decryption processes are multithreaded for optimal performance and efficiency. The number of threads is adjustable.
- **Command and Control (C2)**: After encryption and exfiltration, DarkJester establishes a reverse shell that connects back to the attacker’s machine. This allows the attacker to remotely access the victim’s device and send ransom notes and decryption scripts if the ransom is paid.
- **Persistence Mechanism**: DarkJester adds itself to the Windows registry/Daemon in Linux to ensure it persists through reboots, keeping the reverse shell active even if the victim shuts down the machine.
- **Kiosk Mode (Ransom Note Display)**: DarkJester now features an advanced Kiosk Mode functionality that activates immediately after the encryption process is complete. In this state, the compromised Windows system is locked into a fullscreen environment where normal user interaction is restricted. A persistent ransom note is displayed on-screen, along with a secure input field for entering the decryption key. This immersive mode ensures the victim’s attention is fully directed toward the ransom message, enhancing the psychological pressure often associated with ransomware attacks. Note: This feature is currently supported on Windows operating systems only.

## Installation and Setup

### **Client/Victim Side**

1. **Install Dependencies**:
    - Install all the dependencies needed for DarkJester:
      ```bash
      pip3 install -r requirements.txt
      ```

2. **Configure the payload** by modifying the following parameters:
    - Modify the **IP address** of the reverse shell to the attacker's IP.
    - Modify the **server IP** where the system information and decryption key will be sent.

3. **Compile the payload** into an executable file:
    - Modify the `.spec` file to adjust any customizations if necessary.
    - Compile the `.spec` file using PyInstaller:
      ```bash
      pyinstaller darkjester_encryptor_mass.spec
      ```

4. **Locate the compiled file**:
    - After compilation, the `.exe` file will be available in the `dist/` folder.

5. **Distribute the payload**:
   - The `.exe` file can now be distributed to the target machine. It will run without requiring Python to be installed.

6. **Prepare the attacker machine** before executing the payload on the victim's machine.

---

### **Attacker Side**

1. **Install Dependencies** or just the **Flask**:
    - Install all the dependencies or just the Flask library:
      ```bash
      pip3 install -r requirements.txt
      ```

2. **Run the server**:
    - Ensure the server is set up and running to accept system information and decryption keys:
      ```bash
      python3 darkjester_server.py <EXFIL_PORT> <C2_PORT>
      ```

4. **Wait for connections**, The server should now be ready to handle requests from the victim machine.


## Usage

After both the attacker and victim sides are set up, you can proceed with the following:

1. **Victim Executes Payload**:
    - Once the victim runs the `raw` or `executable` payload, it will encrypt files, exfiltrate data, and establish a reverse shell connection.

2. **Attacker Monitors Connection**:
    - The attacker should monitor the Flask serve and NetCat listener for incoming system information and the reverse shell connection.

3. **Ransom Communication**:
    - The attacker can communicate with the victim through the reverse shell, sending ransom notes or decryption instructions.

## Licence

This tool is provided `as is,` for educational purposes only. The authors and contributors are not responsible for any misuse of this tool. Please adhere to ethical hacking guidelines and obtain proper authorization before using any cybersecurity tools.

## Disclaimer

DarkJester is a powerful ransomware tool developed for educational and research purposes only. 
Unauthorized use of this software is strictly illegal and may result in criminal prosecution. 
Running or deploying DarkJester on any system without explicit permission from the system owner constitutes a violation of cybersecurity laws. 
This tool is intended solely for demonstrating security flaws and testing defenses in controlled environments. 
Always act responsibly and ethically when working with this kind tool.

## Author

- KuroShiro (A1SBERG)
