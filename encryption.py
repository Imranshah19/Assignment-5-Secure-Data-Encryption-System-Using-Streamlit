import hashlib
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Constants
SALT_SIZE = 16
KEY_LENGTH = 32
ITERATIONS = 100000

# Generate a Fernet encryption key using the passkey
def generate_fernet_key(passkey, salt=None):
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    
    # Use PBKDF2 for key derivation
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return Fernet(key), salt

# Hash the passkey (for secure storage and verification)
def hash_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    
    # Use PBKDF2 for password hashing
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
    )
    
    password_hash = kdf.derive(passkey.encode())
    return base64.b64encode(password_hash).decode('utf-8'), base64.b64encode(salt).decode('utf-8')

# Encrypt plain text using the passkey
def encrypt_text(text, passkey):
    key, salt = generate_fernet_key(passkey)
    encrypted = key.encrypt(text.encode())
    return base64.b64encode(encrypted).decode('utf-8'), base64.b64encode(salt).decode('utf-8')

# Decrypt encrypted text using the correct passkey
def decrypt_text(encrypted_text, passkey, salt):
    try:
        salt_bytes = base64.b64decode(salt)
        key, _ = generate_fernet_key(passkey, salt_bytes)
        encrypted_bytes = base64.b64decode(encrypted_text)
        decrypted = key.decrypt(encrypted_bytes)
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

