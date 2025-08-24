#This script is for symmetric encryption and decryption using the 
# cryptography library’s Fernet class. It allows you to securely generate a key, 
# encrypt a message, and decrypt it using the same key.

#Fernet is a module that implements symmetric encryption using a shared secret key
from cryptography.fernet import Fernet

#Generates a secure random key for both encryption and decryption.
def generate_key():  
    return Fernet.generate_key()

#You encrypt a message using Above key.
def encrypt_message(key, message):
    f = Fernet(key)
    return f.encrypt(message.encode())

#You can later decrypt it using the same key.
def decrypt_message(key, token):
    f = Fernet(key)
    return f.decrypt(token).decode()