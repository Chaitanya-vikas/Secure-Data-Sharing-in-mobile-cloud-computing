"""
URL configuration for secure_vault project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
# secure_vault/urls.py
from django.contrib import admin
from django.urls import path

# IMPORT ALL YOUR VIEWS HERE
from core.views import (
    index, 
    download_file, 
    delete_file, 
    signup_view, 
    login_view, 
    logout_view,
    setup_2fa,   # <--- You were likely missing this one
    verify_2fa,   # <--- And this one
    download_encrypted_file,   # <--- IMPORT THIS
    decrypt_tool
)

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Auth Paths
    path('signup/', signup_view, name='signup'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    
    # 2FA Paths
    path('setup-2fa/', setup_2fa, name='setup_2fa'),
    path('verify-2fa/', verify_2fa, name='verify_2fa'),
    
    # App Paths
    path('', index, name='index'),
    path('download/<int:file_id>/', download_file, name='download_file'),

    # NEW PATH
    path('download-enc/<int:file_id>/', download_encrypted_file, name='download_encrypted'),

    path('delete/<int:file_id>/', delete_file, name='delete_file'),
    path('decrypt-tool/', decrypt_tool, name='decrypt_tool'),

]