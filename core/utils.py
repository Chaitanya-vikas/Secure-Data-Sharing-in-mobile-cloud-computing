from cryptography.fernet import Fernet

# REPLACE THE LINE BELOW WITH YOUR GENERATED KEY
# It must start with b' and end with '
KEY = b'xbT_H10SH40LLumM_gfs2kEeHqgQBNa2R6J0q_N3kjk='

cipher = Fernet(KEY)

# core/utils.py (Update only the encrypt function)

def encrypt(data):
    if not data: return None
    
    # If data is text (string), convert to bytes
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    # If data is already bytes (like an image), use it directly
    return cipher.encrypt(data)

# core/utils.py - FINAL VERSION

def decrypt(encrypted_bytes):
    if not encrypted_bytes: return None
    
    decrypted_data = cipher.decrypt(encrypted_bytes)
    
    # Try to convert to text. If it fails, return raw bytes (it's an image)
    try:
        return decrypted_data.decode('utf-8')
    except UnicodeDecodeError:
        return decrypted_data # Return raw bytes for images