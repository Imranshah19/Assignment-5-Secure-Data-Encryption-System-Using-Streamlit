import json
import os
from pathlib import Path
import time

class DataStorage:
    def __init__(self, storage_file='encrypted_data.json'):
        self.storage_file = storage_file
        self.data = self._load_data()
    
    def _load_data(self):
        """Load data from storage file"""
        if not Path(self.storage_file).exists():
            return {}
        
        try:
            with open(self.storage_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
    
    def _save_data(self):
        """Save data to storage file"""
        with open(self.storage_file, 'w') as f:
            json.dump(self.data, f)
    
    def store_data(self, username, encrypted_text, passkey_hash):
        """
        Store encrypted data for a user.
        """
        if username not in self.data:
            self.data[username] = []
        
        # Add timestamp for when the data was stored
        entry = {
            "encrypted_text": encrypted_text,
            "passkey_hash": passkey_hash,
            "timestamp": time.time()
        }
        
        self.data[username].append(entry)
        self._save_data()
        return True
    
    def get_user_data(self, username):
        """
        Get all encrypted data entries for a user.
        """
        return self.data.get(username, [])
    
    def delete_data(self, username, index):
        """
        Delete a specific data entry for a user.
        """
        if username in self.data and 0 <= index < len(self.data[username]):
            del self.data[username][index]
            self._save_data()
            return True
        return False 