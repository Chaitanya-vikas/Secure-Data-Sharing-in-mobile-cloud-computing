from django.db import models
from django.contrib.auth.models import User
from cryptography.fernet import Fernet
import base64

class UserData(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=100)
    encrypted_content = models.BinaryField()
    encrypted_key = models.BinaryField()
    file_extension = models.CharField(max_length=10)
    created_at = models.DateTimeField(auto_now_add=True)
    
    # This allows you to share secrets with other users
    shared_with = models.ManyToManyField(User, related_name='shared_secrets', blank=True)

    # --- CRITICAL FIX: Forces a fresh table 'v4' to bypass errors ---
    class Meta:
        db_table = 'user_data_v4'
    # ---------------------------------------------------------------

    def save_secret(self, content, ext):
        # 1. Generate a random key for this specific file
        key = Fernet.generate_key()
        f = Fernet(key)
        
        # 2. Ensure content is bytes before encrypting
        if isinstance(content, str):
            content = content.encode()
            
        # 3. Encrypt the content
        self.encrypted_content = f.encrypt(content)
        
        # 4. Save the key (encrypted/encoded for safe storage)
        self.encrypted_key = base64.urlsafe_b64encode(key)
        self.file_extension = ext
        self.save()

    def get_secret(self):
        # 1. Decode the stored key
        key = base64.urlsafe_b64decode(self.encrypted_key)
        f = Fernet(key)
        
        # 2. Decrypt the content
        decrypted_data = f.decrypt(self.encrypted_content)
        return decrypted_data