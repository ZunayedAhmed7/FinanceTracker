import os
import hashlib
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()
key = os.getenv("FERNET_KEY")  # Load key from .env

cipher_suite = Fernet(key.encode())

def encrypt_data(data):
    return cipher_suite.encrypt(data.encode('utf-8'))

def decrypt_data(encrypted_data):
    return cipher_suite.decrypt(encrypted_data).decode('utf-8')

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt + hashed_password

def verify_password(stored_password, input_password):
    salt = stored_password[:16]
    hashed_password = stored_password[16:]
    new_hash = hashlib.pbkdf2_hmac('sha256', input_password.encode('utf-8'), salt, 100000)
    return hashed_password == new_hash

print(f"Loaded FERNET_KEY: {os.getenv('FERNET_KEY')}")
