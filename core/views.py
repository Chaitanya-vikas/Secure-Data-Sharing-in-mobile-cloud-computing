import os
import io
import base64
import qrcode
import re
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse

# --- NEW: Import Django's random string generator ---
from django.utils.crypto import get_random_string

# --- AUTH & SECURITY IMPORTS ---
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import login, logout
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.plugins.otp_static.models import StaticDevice
from django_otp import login as otp_login
from django_otp import match_token
from cryptography.fernet import InvalidToken

# --- APP IMPORTS ---
from .models import UserData

def landing_page(request):
    return render(request, 'landing.html')

def is_2fa_verified(user):
    return user.is_authenticated and user.is_verified()

def signup_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('setup_2fa') 
    else:
        form = UserCreationForm()
    return render(request, 'signup.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            if TOTPDevice.objects.filter(user=user, confirmed=True).exists():
                return redirect('verify_2fa')
            else:
                return redirect('setup_2fa')
    else:
        form = AuthenticationForm()
    return render(request, 'login.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('login')

@login_required(login_url='login')
def setup_2fa(request):
    user = request.user

    # 1. Check if already fully secured
    if TOTPDevice.objects.filter(user=user, confirmed=True).exists():
        if request.method == 'POST' and request.POST.get('reset') == 'true':
            print(f"--- 🔴 RESETTING ALL KEYS FOR {user.username} ---")
            TOTPDevice.objects.filter(user=user).delete()
            StaticDevice.objects.filter(user=user).delete()
            return redirect('setup_2fa')
            
        elif request.method == 'POST' and request.POST.get('generate_backups') == 'true':
            StaticDevice.objects.filter(user=user).delete() 
            static_device = StaticDevice.objects.create(user=user, name="Backup Codes")
            backup_codes = []
            for _ in range(5):
                # FIX: Explicitly generate a 10-character random string!
                code = get_random_string(length=10, allowed_chars='abcdefghjkmnpqrstuvwxyz23456789')
                static_device.token_set.create(token=code)
                backup_codes.append(code)
            return render(request, 'setup_2fa.html', {'backup_codes': backup_codes})
            
        return render(request, 'setup_2fa.html', {'already_setup': True})

    # 2. GUARANTEE an unconfirmed device exists for the QR code
    device = TOTPDevice.objects.filter(user=user, confirmed=False).last()
    if not device:
        # We keep tolerance=60 to absorb any local computer clock glitches!
        device = TOTPDevice.objects.create(user=user, name="Default", tolerance=60)
        print(f"--- 🆕 CREATED NEW SECRET KEY FOR {user.username} ---")

    # 3. Handle Token Verification
    if request.method == 'POST' and request.POST.get('token'):
        token = request.POST.get('token').replace(' ', '').strip()
        print(f"--- 🔐 2FA VERIFICATION ATTEMPT ---")
        print(f"User Typed Code : {token}")
        
        if device.verify_token(token):
            print("--- ✅ VERIFICATION SUCCESSFUL! ---")
            device.confirmed = True
            device.save()
            
            # Cleanup leftover keys and generate backups
            TOTPDevice.objects.filter(user=user, confirmed=False).delete()
            StaticDevice.objects.filter(user=user).delete() 
            static_device = StaticDevice.objects.create(user=user, name="Backup Codes")
            
            backup_codes = []
            for _ in range(5):
                # FIX: Explicitly generate a 10-character random string!
                code = get_random_string(length=10, allowed_chars='abcdefghjkmnpqrstuvwxyz23456789')
                static_device.token_set.create(token=code)
                backup_codes.append(code)
                
            return render(request, 'setup_2fa.html', {'backup_codes': backup_codes})
        else:
            print("--- ❌ VERIFICATION FAILED (INVALID MATH) ---")
            otp_url = device.config_url
            img = qrcode.make(otp_url)
            buffer = io.BytesIO()
            img.save(buffer)
            qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            return render(request, 'setup_2fa.html', {
                'error': 'Invalid Code. Please try again.', 
                'qr_code': qr_code_base64
            })

    # 4. Default GET Behavior: Render the QR code
    otp_url = device.config_url
    img = qrcode.make(otp_url)
    buffer = io.BytesIO()
    img.save(buffer)
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()

    return render(request, 'setup_2fa.html', {'qr_code': qr_code_base64})

@login_required(login_url='login')
def verify_2fa(request):
    if not TOTPDevice.objects.filter(user=request.user, confirmed=True).exists():
        return redirect('setup_2fa')

    if request.method == 'POST':
        token = request.POST.get('token', '').replace(' ', '').strip()
        user = request.user
        
        device = match_token(user, token)
        
        if device:
            otp_login(request, device)
            return redirect('dashboard')
        else:
            return render(request, 'verify_2fa.html', {'error': 'Invalid 2FA Code'})
            
    return render(request, 'verify_2fa.html')

@user_passes_test(is_2fa_verified, login_url='verify_2fa')
def index(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        secret_text = request.POST.get('secret_text')
        secret_file = request.FILES.get('secret_file')
        
        new_entry = UserData(title=title, user=request.user)
        
        if secret_file:
            ext = os.path.splitext(secret_file.name)[1]
            file_data = secret_file.read() 
            new_entry.save_secret(file_data, ext)
        elif secret_text:
            new_entry.save_secret(secret_text, '.txt')
            
        return redirect('dashboard')

    all_data = UserData.objects.filter(user=request.user)
    return render(request, 'index.html', {'all_data': all_data})

@user_passes_test(is_2fa_verified, login_url='verify_2fa')
def download_file(request, file_id):
    entry = get_object_or_404(UserData, pk=file_id, user=request.user)
    decrypted_content = entry.get_secret()
    
    content_type = 'text/plain'
    if entry.file_extension in ['.jpg', '.jpeg']:
        content_type = 'image/jpeg'
    elif entry.file_extension == '.png':
        content_type = 'image/png'
        
    response = HttpResponse(decrypted_content, content_type=content_type)
    response['Content-Disposition'] = f'attachment; filename="{entry.title}{entry.file_extension}"'
    return response

@user_passes_test(is_2fa_verified, login_url='verify_2fa')
def delete_file(request, file_id):
    if request.method == 'POST':
        entry = get_object_or_404(UserData, pk=file_id, user=request.user)
        entry.delete()
    return redirect('dashboard')

@user_passes_test(is_2fa_verified, login_url='verify_2fa')
def download_encrypted_file(request, file_id):
    entry = get_object_or_404(UserData, pk=file_id, user=request.user)
    raw_data = entry.encrypted_content
    response = HttpResponse(raw_data, content_type='application/octet-stream')
    
    filename = f"ID_{entry.id}_{entry.title}_encrypted.bin"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response

@user_passes_test(is_2fa_verified, login_url='verify_2fa')
def decrypt_tool(request):
    user_secrets = UserData.objects.filter(user=request.user)
    decrypted_text = None
    decrypted_image = None
    error_message = None

    if request.method == 'POST':
        uploaded_file = request.FILES.get('encrypted_file')
        secret_id = request.POST.get('secret_id')
        
        if uploaded_file:
            try:
                if not secret_id:
                    match = re.search(r'ID_(\d+)_', uploaded_file.name)
                    if match:
                        secret_id = match.group(1)
                
                if not secret_id:
                    raise Exception("Could not detect Secret ID from filename. Please select the Key manually.")

                entry = get_object_or_404(UserData, pk=secret_id)
                
                file_bytes = uploaded_file.read()
                entry.encrypted_content = file_bytes 
                
                raw_result = entry.get_secret()
                
                if entry.file_extension in ['.jpg', '.jpeg', '.png']:
                    import base64
                    if isinstance(raw_result, str):
                        raw_result = raw_result.encode('utf-8')
                        
                    b64_img = base64.b64encode(raw_result).decode('utf-8')
                    mime_type = 'image/jpeg' if 'jpg' in entry.file_extension else 'image/png'
                    decrypted_image = f"data:{mime_type};base64,{b64_img}"
                else:
                    if isinstance(raw_result, bytes):
                        decrypted_text = raw_result.decode('utf-8')
                    else:
                        decrypted_text = raw_result

            except InvalidToken:
                error_message = "❌ Decryption Failed: The file content does not match the Key for ID #" + str(secret_id)
            except Exception as e:
                error_message = f"❌ Error: {str(e)}"

    return render(request, 'decrypt_tool.html', {
        'user_secrets': user_secrets,
        'decrypted_text': decrypted_text,
        'decrypted_image': decrypted_image,
        'error_message': error_message
    })