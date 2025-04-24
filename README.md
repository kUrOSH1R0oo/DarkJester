# DarkJester: A Powerful and Fully Python-based Advanced Ransomware

![GIF](https://github.com/Kuraiyume/DarkJester/blob/main/Art.gif)

**DarkJester** is an advanced ransomware developed in Python, offering a wide range of capabilities that set it apart from typical ransomware. It is highly modular and adaptable, allowing seamless integration of additional features. DarkJester combines destructive ransomware tactics with advanced espionage capabilities, including file encryption, reverse shell mechanisms, and system reconnaissance.

## Features

| Feature                          | Description |
|----------------------------------|-------------|
| **AES-256 Encryption**           | Implements the Advanced Encryption Standard (AES) with a 256-bit key in Cipher Block Chaining (CBC) mode to ensure high-level data security. This symmetric encryption technique makes decryption virtually impossible without the correct key, making it ideal for securing victim files during a ransomware attack. |
| **File Exfiltration**            | Prior to encryption, sensitive files are identified, collected, and transmitted to a remote server in their original, unencrypted state. This enables the attacker to retain access to the victim’s data, even if decryption is attempted independently, increasing leverage for ransom demands. |
| **Key and System Exfiltration**  | The generated encryption key, along with detailed information about the victim’s system — such as operating system, CPU model, system architecture, MAC address, and hostname — is stealthily sent to the attacker's server. This helps the attacker uniquely identify victims and manage decryptions post-payment. |
| **Multithreaded Encryption/Decryption** | Encryption and decryption operations are executed using multiple threads simultaneously, significantly improving speed and performance. The thread count is adjustable, allowing the malware to adapt to different system capabilities for optimal efficiency. |
| **Command and Control (C2)**     | After the encryption and exfiltration processes are completed, a reverse shell is established to connect the victim’s machine back to the attacker. Through this persistent shell, the attacker can execute commands, drop additional payloads, and send decryption tools or ransom notes if payment is made. |
| **Persistence Mechanism**        | DarkJester ensures its survival after system reboots by registering itself in the Windows Registry (or setting up a daemon/service on Linux systems). This mechanism allows the malware to reinitialize upon system startup, maintaining control over the compromised machine. |
| **Kiosk Mode (Ransom Note Display)** | Once file encryption concludes, the malware activates Kiosk Mode, locking the system into a fullscreen, restricted environment. All standard user interactions are disabled. A prominently displayed ransom message informs the victim of the breach and provides a secure text field for inputting the decryption key. This immersive experience is designed to maximize psychological pressure and urgency. Note: This feature is only supported on Windows operating systems. |


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

3. **Compile the payload** into an executable file (Optional):
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

**NOTE: For testing, it's better to use the specific version!**

---

### **Attacker Side**

1. **Install Dependencies**:
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
    - When the victim executes the `raw` or `compiled` payload, it will initiate file encryption, extract sensitive data, connect to the command-and-control (C2) server, and activate kiosk mode on the system.

2. **Attacker Monitors Connection**:
    - The attacker should monitor the server for incoming system information and the C2 connection.

3. **Device Communication**:
    - The attacker can communicate with the victim's device through C2.

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
