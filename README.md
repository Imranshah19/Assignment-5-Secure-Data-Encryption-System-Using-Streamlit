# Secure Data Encryption System

A streamlit-based application for secure data encryption and decryption using industry-standard cryptographic techniques.

## Features

- **Text Encryption/Decryption:** Securely encrypt and decrypt text messages
- **File Encryption/Decryption:** Protect files with strong encryption
- **User Authentication:** Secure user accounts with password hashing
- **Easy-to-Use Interface:** Simple and intuitive UI built with Streamlit

## Installation

1. Clone this repository
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```
   streamlit run app.py
   ```

2. Open your browser and navigate to the URL shown in the terminal (usually http://localhost:8501)

3. Register a new account or log in with existing credentials

4. Use the different tabs to encrypt/decrypt text or files

## Security Features

- Strong encryption using Fernet (AES-128 in CBC mode with PKCS7 padding)
- Password-based key derivation using PBKDF2
- Secure password hashing for user authentication
- Random salt generation for each encryption operation

## Project Structure

- `app.py` - Main Streamlit application (UI & routing)
- `encryption.py` - Encryption and decryption functionality
- `auth.py` - User authentication and password hashing

## Requirements

- Python 3.7+
- Streamlit
- Cryptography

## License

MIT 