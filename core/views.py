import os
import io
import base64
import qrcode
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse

# --- AUTH & SECURITY IMPORTS ---
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import login, logout
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp import login as otp_login

# --- APP IMPORTS ---
from .models import UserData

# ==========================================
# 1. SECURITY HELPER
# ==========================================

def is_2fa_verified(user):
    """
    Checks if the user is logged in AND has passed the 2FA check.
    If they are logged in but haven't entered the code yet, this returns False.
    """
    return user.is_authenticated and user.is_verified()


# ==========================================
# 2. AUTHENTICATION VIEWS (Signup, Login, 2FA)
# ==========================================

def signup_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            # Redirect to 2FA setup immediately after signup
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
            
            # Check if user has 2FA setup
            if TOTPDevice.objects.filter(user=user, confirmed=True).exists():
                return redirect('verify_2fa') # Go to Step 2
            else:
                return redirect('setup_2fa') # Force them to setup 2FA
    else:
        form = AuthenticationForm()
    return render(request, 'login.html', {'form': form})


def logout_view(request):
    logout(request)
    return redirect('login')


@login_required(login_url='login')
def setup_2fa(request):
    user = request.user

    # --- NEW: RESET LOGIC ---
    if request.method == 'POST' and request.POST.get('reset') == 'true':
        # Delete all 2FA devices for this user so they can start over
        TOTPDevice.objects.filter(user=user).delete()
        return redirect('setup_2fa')
    # ------------------------
    
    # Check if user already has a device (and hasn't asked to reset)
    devices = TOTPDevice.objects.filter(user=user, confirmed=True)
    if devices.exists():
        return render(request, 'setup_2fa.html', {'already_setup': True})

    if request.method == 'POST':
        # Verify the code entered by the user
        token = request.POST.get('token')
        device = TOTPDevice.objects.filter(user=user, confirmed=False).first()
        
        if device and device.verify_token(token):
            device.confirmed = True
            device.save()
            return redirect('index')
        else:
            return render(request, 'setup_2fa.html', {'error': 'Invalid Code', 'device': device})

    # Generate a new unconfirmed device/secret
    TOTPDevice.objects.filter(user=user, confirmed=False).delete()
    device = TOTPDevice.objects.create(user=user, name="Default")
    
    # Generate QR Code
    otp_url = device.config_url
    img = qrcode.make(otp_url)
    buffer = io.BytesIO()
    img.save(buffer)
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()

    return render(request, 'setup_2fa.html', {'qr_code': qr_code_base64})

# core/views.py

@login_required(login_url='login')
def verify_2fa(request):
    # FIX: Check if user actually has a 2FA device confirmed.
    # If not, redirect them to setup immediately.
    if not TOTPDevice.objects.filter(user=request.user, confirmed=True).exists():
        return redirect('setup_2fa')

    if request.method == 'POST':
        token = request.POST.get('token')
        user = request.user
        
        device = TOTPDevice.objects.filter(user=user, confirmed=True).first()
        
        if device and device.verify_token(token):
            otp_login(request, device)
            return redirect('index')
        else:
            return render(request, 'verify_2fa.html', {'error': 'Invalid 2FA Code'})
            
    return render(request, 'verify_2fa.html')


# ==========================================
# 3. APP FUNCTIONALITY (Secure Vault)
# ==========================================

# NOTE: We use @user_passes_test instead of @login_required here
# This ensures they have passed the 2FA check, not just the password check.
@user_passes_test(is_2fa_verified, login_url='verify_2fa')
def index(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        secret_text = request.POST.get('secret_text')
        secret_file = request.FILES.get('secret_file') # Get uploaded file
        
        # Create object specifically for the logged-in user
        new_entry = UserData(title=title, user=request.user)
        
        if secret_file:
            # IT IS AN IMAGE/FILE
            # 1. Get the extension (e.g., .jpg)
            ext = os.path.splitext(secret_file.name)[1]
            # 2. Read the raw bytes from memory
            file_data = secret_file.read() 
            # 3. Encrypt and Save
            new_entry.save_secret(file_data, ext)
            
        elif secret_text:
            # IT IS TEXT
            new_entry.save_secret(secret_text, '.txt')
            
        return redirect('index')

    # Filter data: Show ONLY the logged-in user's secrets
    all_data = UserData.objects.filter(user=request.user)
    return render(request, 'index.html', {'all_data': all_data})


@user_passes_test(is_2fa_verified, login_url='verify_2fa')
def download_file(request, file_id):
    # Security Check: Ensure the file belongs to the logged-in user
    entry = get_object_or_404(UserData, pk=file_id, user=request.user)
    
    decrypted_content = entry.get_secret()
    
    # Determine Content Type based on extension
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
        # Security Check: Ensure user owns the file before deleting
        entry = get_object_or_404(UserData, pk=file_id, user=request.user)
        entry.delete()
    return redirect('index')

# Add this to the bottom of core/views.py

# In core/views.py

@user_passes_test(is_2fa_verified, login_url='verify_2fa')
def download_encrypted_file(request, file_id):
    entry = get_object_or_404(UserData, pk=file_id, user=request.user)
    raw_data = entry.encrypted_content
    response = HttpResponse(raw_data, content_type='application/octet-stream')
    
    # NEW: We put the ID in the filename (e.g., "ID_4_BankPass.bin")
    filename = f"ID_{entry.id}_{entry.title}_encrypted.bin"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    return response

    # Add this to the bottom of core/views.py
from cryptography.fernet import InvalidToken # Import for error handling

# Replace your existing decrypt_tool function in core/views.py

# In core/views.py

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
                # 1. Auto-detect ID from filename if not selected
                if not secret_id:
                    import re
                    match = re.search(r'ID_(\d+)_', uploaded_file.name)
                    if match:
                        secret_id = match.group(1)
                
                if not secret_id:
                    raise Exception("Could not detect Secret ID from filename. Please select the Key manually.")

                # 2. Get the Key Object
                entry = get_object_or_404(UserData, pk=secret_id, user=request.user)
                
                # 3. Read uploaded bytes and Swap
                file_bytes = uploaded_file.read()
                entry.encrypted_content = file_bytes 
                
                # 4. Decrypt
                raw_result = entry.get_secret()
                
                # 5. Handle Image vs Text (WITH FIX)
                if entry.file_extension in ['.jpg', '.jpeg', '.png']:
                    import base64
                    # If raw_result is already a string (rare but possible), encode it back to bytes first
                    if isinstance(raw_result, str):
                        raw_result = raw_result.encode('utf-8')
                        
                    b64_img = base64.b64encode(raw_result).decode('utf-8')
                    mime_type = 'image/jpeg' if 'jpg' in entry.file_extension else 'image/png'
                    decrypted_image = f"data:{mime_type};base64,{b64_img}"
                else:
                    # --- THE FIX IS HERE ---
                    if isinstance(raw_result, bytes):
                        # If it's bytes, we decode it to string
                        decrypted_text = raw_result.decode('utf-8')
                    else:
                        # If it's already a string, we just use it
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