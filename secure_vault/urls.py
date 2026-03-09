from django.contrib import admin
from django.urls import path
from core import views

from core.views import (
    index, 
    download_file, 
    delete_file, 
    signup_view, 
    login_view, 
    logout_view,
    setup_2fa,
    verify_2fa,
    download_encrypted_file,
    decrypt_tool
)

urlpatterns = [
    path('admin/', admin.site.urls),

    # Landing page stays at the root URL (e.g., localhost:8000/)
    path('', views.landing_page, name='landing'),
    
    # Auth Paths
    path('signup/', signup_view, name='signup'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    
    # 2FA Paths
    path('setup-2fa/', setup_2fa, name='setup_2fa'),
    path('verify-2fa/', verify_2fa, name='verify_2fa'),
    
    # App Paths
    # FIX: We moved your main app to /dashboard/ and named it 'dashboard'
    path('dashboard/', index, name='dashboard'), 
    
    path('download/<int:file_id>/', download_file, name='download_file'),
    path('download-enc/<int:file_id>/', download_encrypted_file, name='download_encrypted'),
    path('delete/<int:file_id>/', delete_file, name='delete_file'),
    path('decrypt-tool/', decrypt_tool, name='decrypt_tool'),
]