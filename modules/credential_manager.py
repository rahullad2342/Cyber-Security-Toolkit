# This script is used to store and retrieve encrypted credentials 
# (like usernames and passwords) using the cryptography.fernet module.

import json  # Used for read/write data in JSON format.
import os    # Used here to check if a file exists.
from cryptography.fernet import Fernet  # Provides symmetric encryption/decryption using a secret key.

# It will save and read credentials from this JSON file.
CRED_FILE = "data/credentials.json"

#Save credentials securely
def save_credentials(service, username, password, key):
    data = {}  # It will hold all credential records.

    # Load existing data if the file exists
    if os.path.exists(CRED_FILE):
        with open(CRED_FILE, "r") as f:
            data = json.load(f)

    # Encrypt and update the data dictionary
    cipher = Fernet(key)
    data[service] = {
        "username": username,
        "password": cipher.encrypt(password.encode()).decode()
    }

    # Save updated data to JSON
    with open(CRED_FILE, "w") as f:
        json.dump(data, f, indent=4)


#Retrieve credentials securely
def get_credentials(service, key):
    if not os.path.exists(CRED_FILE):
        return None  # No file, nothing to retrieve

    with open(CRED_FILE, "r") as f:
        data = json.load(f)

    cipher = Fernet(key)
    record = data.get(service)

    if record:
        try:
            decrypted_password = cipher.decrypt(record["password"].encode()).decode()
            return record["username"], decrypted_password
        except Exception:
            return None  # Decryption failed due to wrong key or corrupted data
    return None

#Optional: Save/load key to/from a file
def save_key_to_file(key, filename="data/secret.key"):
    with open(filename, "wb") as f:
        f.write(key)

def load_key_from_file(filename="data/secret.key"):
    with open(filename, "rb") as f:
        return f.read()
