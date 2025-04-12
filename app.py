# app.py

import streamlit as st
import time
import os
from encryption import encrypt_text, decrypt_text
from auth import UserAuthManager
from data_storage import DataStorage

# Initialize managers with proper error handling
try:
    auth_manager = UserAuthManager()
    data_storage = DataStorage()
except Exception as e:
    st.error(f"Error initializing application: {str(e)}")
    st.stop()

# App configuration
st.set_page_config(
    page_title="Secure Data Encryption System",
    page_icon="🔒",
    layout="wide",
)

# Create session states
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'username' not in st.session_state:
    st.session_state.username = None

# CSS styling
st.markdown("""
<style>
    .main {
        padding: 2rem;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 1rem;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 4px 4px 0 0;
        padding: 10px 20px;
        background-color: #f0f2f6;
    }
    .stTabs [aria-selected="true"] {
        background-color: #ffffff;
        border-bottom: 2px solid #4CAF50;
    }
    .encrypt-box {
        background-color: #e8f5e9;
        padding: 20px;
        border-radius: 10px;
        margin-bottom: 20px;
    }
    .decrypt-box {
        background-color: #e8eaf6;
        padding: 20px;
        border-radius: 10px;
        margin-bottom: 20px;
    }
    .data-entry {
        background-color: #f5f5f5;
        padding: 15px;
        border-radius: 8px;
        margin-bottom: 10px;
        border-left: 4px solid #4CAF50;
    }
</style>
""", unsafe_allow_html=True)

# Authentication functions
def login():
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
        
        if submit:
            success, message = auth_manager.authenticate_user(username, password)
            if success:
                st.session_state.authenticated = True
                st.session_state.username = username
                st.success(message)
                st.rerun()
            else:
                st.error(message)

def register():
    with st.form("register_form"):
        username = st.text_input("Choose a Username")
        password = st.text_input("Create a Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        submit = st.form_submit_button("Register")
        
        if submit:
            if password != confirm_password:
                st.error("Passwords do not match!")
            elif not username or not password:
                st.error("Username and password cannot be empty!")
            else:
                if auth_manager.register_user(username, password):
                    st.success("Registration successful! You can now log in.")
                else:
                    st.error("Username already exists. Please choose another one.")

def logout():
    st.session_state.authenticated = False
    st.session_state.username = None
    st.rerun()

# Data management functions
def store_data():
    st.markdown('<div class="encrypt-box">', unsafe_allow_html=True)
    
    text = st.text_area("Enter your secret data", height=150)
    passkey = st.text_input("Enter a passkey", type="password")
    
    if st.button("Encrypt and Store"):
        if text and passkey:
            # Encrypt the text
            encrypted_text, salt = encrypt_text(text, passkey)
            
            # Store the encrypted data
            data_storage.store_data(st.session_state.username, encrypted_text, salt)
            
            st.success("Data stored successfully!")
        else:
            st.error("Please provide both text and passkey!")
    
    st.markdown('</div>', unsafe_allow_html=True)

def retrieve_data():
    st.markdown('<div class="decrypt-box">', unsafe_allow_html=True)
    
    # Get user's stored data
    user_data = data_storage.get_user_data(st.session_state.username)
    
    if not user_data:
        st.info("You don't have any stored data yet.")
        return
    
    # Display stored data entries
    st.subheader("Your Stored Data")
    
    for i, entry in enumerate(user_data):
        with st.expander(f"Data Entry {i+1} - {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(entry['timestamp']))}"):
            st.markdown('<div class="data-entry">', unsafe_allow_html=True)
            
            # Decryption form
            with st.form(f"decrypt_form_{i}"):
                passkey = st.text_input("Enter your passkey", type="password", key=f"passkey_{i}")
                submit = st.form_submit_button("Decrypt")
                
                if submit and passkey:
                    decrypted = decrypt_text(entry["encrypted_text"], passkey, entry["passkey_hash"])
                    
                    if decrypted:
                        st.success("Decryption successful!")
                        st.text_area("Decrypted text:", decrypted, height=100)
                    else:
                        st.error("Decryption failed. Check your passkey.")
            
            # Delete button
            if st.button("Delete this entry", key=f"delete_{i}"):
                if data_storage.delete_data(st.session_state.username, i):
                    st.success("Entry deleted successfully!")
                    st.rerun()
                else:
                    st.error("Failed to delete entry.")
            
            st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown('</div>', unsafe_allow_html=True)

def account_settings():
    st.markdown("## Account Settings")
    
    with st.form("change_password_form"):
        current_password = st.text_input("Current Password", type="password")
        new_password = st.text_input("New Password", type="password")
        confirm_password = st.text_input("Confirm New Password", type="password")
        submit = st.form_submit_button("Change Password")
        
        if submit:
            if new_password != confirm_password:
                st.error("New passwords do not match!")
            elif not current_password or not new_password:
                st.error("All fields are required!")
            else:
                success, message = auth_manager.change_password(
                    st.session_state.username, 
                    current_password, 
                    new_password
                )
                if success:
                    st.success(message)
                else:
                    st.error(message)
    
    with st.form("delete_account_form"):
        st.subheader("Delete Account")
        password = st.text_input("Enter your password to confirm", type="password")
        submit = st.form_submit_button("Delete Account")
        
        if submit:
            if not password:
                st.error("Password is required!")
            else:
                success, message = auth_manager.delete_user(st.session_state.username, password)
                if success:
                    st.success(message)
                    logout()
                else:
                    st.error(message)

# Main App Content
def main():
    st.title("🔒 Secure Data Encryption System")
    
    if not st.session_state.authenticated:
        tab1, tab2 = st.tabs(["Login", "Register"])
        
        with tab1:
            login()
        
        with tab2:
            register()
    
    else:
        st.sidebar.success(f"Logged in as: {st.session_state.username}")
        st.sidebar.button("Logout", on_click=logout)
        
        # Main navigation
        tab1, tab2, tab3 = st.tabs(["Store Data", "Retrieve Data", "Account Settings"])
        
        with tab1:
            st.markdown("## 📝 Store Secure Data")
            store_data()
        
        with tab2:
            st.markdown("## 🔓 Retrieve Your Data")
            retrieve_data()
        
        with tab3:
            account_settings()

if __name__ == "__main__":
    main()
