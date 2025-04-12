import hashlib
import os
import hmac
import base64
import json
import time
from pathlib import Path

# Constants
SALT_SIZE = 16
KEY_LENGTH = 32
ITERATIONS = 100000
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_DURATION = 300  # 5 minutes in seconds

def hash_password(password, salt=None):
    """
    Generate a secure hash of the password using PBKDF2.
    Returns the hash and salt used.
    """
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        ITERATIONS,
        KEY_LENGTH
    )
    
    return password_hash, salt

def verify_password(password, stored_hash, salt):
    """
    Verify a password against a stored hash.
    """
    password_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(password_hash, stored_hash)

class UserAuthManager:
    def __init__(self, storage_file='users.json'):
        self.storage_file = storage_file
        self.users = self._load_users()
        self.failed_attempts = {}
        self.lockout_until = {}
    
    def _load_users(self):
        """Load user data from storage file"""
        if not Path(self.storage_file).exists():
            return {}
        
        try:
            with open(self.storage_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
    
    def _save_users(self):
        """Save user data to storage file"""
        with open(self.storage_file, 'w') as f:
            json.dump(self.users, f)
    
    def _hash_password(self, password, salt=None):
        """Generate a secure hash of the password using PBKDF2"""
        if salt is None:
            salt = os.urandom(SALT_SIZE)
        
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            ITERATIONS,
            KEY_LENGTH
        )
        
        return password_hash, salt
    
    def _verify_password(self, password, stored_hash, salt):
        """Verify a password against a stored hash"""
        password_hash, _ = self._hash_password(password, salt)
        return hmac.compare_digest(password_hash, stored_hash)
    
    def register_user(self, username, password):
        """
        Register a new user.
        Returns True on success, False if user already exists.
        """
        if username in self.users:
            return False
        
        password_hash, salt = self._hash_password(password)
        
        self.users[username] = {
            'hash': base64.b64encode(password_hash).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8')
        }
        
        self._save_users()
        return True
    
    def authenticate_user(self, username, password):
        """
        Authenticate a user with username and password.
        Returns True if authentication is successful, False otherwise.
        """
        # Check if user is locked out
        if username in self.lockout_until:
            if time.time() < self.lockout_until[username]:
                remaining_time = int(self.lockout_until[username] - time.time())
                return False, f"Account locked. Try again in {remaining_time} seconds."
            else:
                # Lockout period has expired
                del self.lockout_until[username]
                self.failed_attempts[username] = 0
        
        if username not in self.users:
            return False, "User not found."
        
        user_data = self.users[username]
        stored_hash = base64.b64decode(user_data['hash'])
        salt = base64.b64decode(user_data['salt'])
        
        if self._verify_password(password, stored_hash, salt):
            # Reset failed attempts on successful login
            self.failed_attempts[username] = 0
            return True, "Authentication successful."
        else:
            # Increment failed attempts
            self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1
            
            # Check if user should be locked out
            if self.failed_attempts[username] >= MAX_FAILED_ATTEMPTS:
                self.lockout_until[username] = time.time() + LOCKOUT_DURATION
                return False, f"Too many failed attempts. Account locked for {LOCKOUT_DURATION} seconds."
            
            remaining_attempts = MAX_FAILED_ATTEMPTS - self.failed_attempts[username]
            return False, f"Invalid password. {remaining_attempts} attempts remaining."
    
    def change_password(self, username, current_password, new_password):
        """
        Change a user's password.
        Returns True on success, False if authentication fails.
        """
        success, message = self.authenticate_user(username, current_password)
        if not success:
            return False, message
        
        password_hash, salt = self._hash_password(new_password)
        
        self.users[username] = {
            'hash': base64.b64encode(password_hash).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8')
        }
        
        self._save_users()
        return True, "Password changed successfully."
    
    def delete_user(self, username, password):
        """
        Delete a user account.
        Returns True on success, False if authentication fails.
        """
        success, message = self.authenticate_user(username, password)
        if not success:
            return False, message
        
        del self.users[username]
        self._save_users()
        return True, "User account deleted successfully." 