from django.db import models
from django.contrib.auth.models import User
from .utils import encrypt, decrypt

class UserData(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    encrypted_content = models.BinaryField()
    
    # New field to remember if it is .txt, .jpg, .png, etc.
    file_extension = models.CharField(max_length=10, default='.txt')

    def save_secret(self, data, ext='.txt'):
        # data can be text or bytes now
        self.encrypted_content = encrypt(data)
        self.file_extension = ext
        self.save()

    def get_secret(self):
        return decrypt(self.encrypted_content)