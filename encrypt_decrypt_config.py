import os
from cryptography.fernet import Fernet
from getpass import getpass
import base64
import hashlib

CONFIG_FILE = "config/.env"  # Path to your .env file
ENCRYPTED_FILE = "config/encrypted_env.enc"  # Path to the encrypted file

def generate_key(password):
    """Generate a key based on a password."""
    # Create a SHA256 hash of the password
    password_bytes = password.encode()
    key = hashlib.sha256(password_bytes).digest()
    # Use base64 encoding to generate a Fernet key
    return base64.urlsafe_b64encode(key)

def encrypt_file(password):
    """Encrypt the config file and save it as encrypted_env.enc."""
    if not os.path.exists('config'):
        os.makedirs('config')  # Create the config directory if it doesn't exist

    # Read the content of the .env file
    with open(CONFIG_FILE, 'rb') as f:
        data = f.read()

    # Encrypt the data with the password-derived key
    key = generate_key(password)
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(data)

    # Save encrypted data to file
    with open(ENCRYPTED_FILE, 'wb') as f:
        f.write(encrypted_data)

    print(f"🔒 Config file encrypted as {ENCRYPTED_FILE}")

def decrypt_file(password):
    """Decrypt the encrypted_env.enc file back to .env."""
    if not os.path.exists(ENCRYPTED_FILE):
        print("❌ Encrypted file not found. Make sure you have encrypted it first.")
        return

    with open(ENCRYPTED_FILE, 'rb') as f:
        encrypted_data = f.read()

    key = generate_key(password)
    cipher = Fernet(key)

    try:
        decrypted_data = cipher.decrypt(encrypted_data)
        with open(CONFIG_FILE, 'wb') as f:
            f.write(decrypted_data)
        print(f"🔓 Config file decrypted as {CONFIG_FILE}")
    except Exception as e:
        print("❌ Decryption failed. Check your password.")
        raise e

if __name__ == "__main__":
    action = input("Do you want to (e)ncrypt or (d)ecrypt the config file? ")
    password = getpass("Enter encryption password: ")

    if action.lower() == 'e':
        encrypt_file(password)
    elif action.lower() == 'd':
        decrypt_file(password)
    else:
        print("Invalid action. Choose either (e)ncrypt or (d)ecrypt.")
