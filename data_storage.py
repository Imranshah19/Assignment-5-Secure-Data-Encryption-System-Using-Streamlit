import json
import os
from pathlib import Path
import time

class DataStorage:
    def __init__(self, storage_file='encrypted_data.json'):
        # Create a data directory if it doesn't exist
        self.data_dir = Path('data')
        self.data_dir.mkdir(exist_ok=True)
        
        # Use the data directory for storage
        self.storage_file = self.data_dir / storage_file
        self.data = self._load_data()
    
    def _load_data(self):
        """Load data from storage file"""
        if not self.storage_file.exists():
            return {}
        
        try:
            with open(self.storage_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
    
    def _save_data(self):
        """Save data to storage file"""
        try:
            with open(self.storage_file, 'w') as f:
                json.dump(self.data, f)
        except Exception as e:
            print(f"Error saving data: {str(e)}")
            return False
        return True
    
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