from django.shortcuts import render, redirect, get_object_or_404
from django.http import FileResponse, Http404
from .models import Certificate, CertificateRenewal
from .forms import CertificateForm, CertificateRenewalForm
from django.contrib import messages
from django.utils.timezone import now
import json
import os
from django.core.exceptions import ValidationError
from django.shortcuts import redirect
from .utils import update_credentials_file
import logging
from django.shortcuts import render, redirect
import logging
import os
import json
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.urls import reverse
from authlib.integrations.django_client import OAuth

import os
import json
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.urls import reverse
from django.contrib import messages
from authlib.integrations.django_client import OAuth

# OAuth Configuration
CONF_URL = 'https://sso-uat.iitb.ac.in/.well-known/openid-configuration'

oauth = OAuth()
oauth.register(
    name='certs_iitb',
    client_id='testpkiserver',  # Replace with actual client ID
    client_secret='NTTwiM2mvk6tePajZqTD7Jd5ZXTnIr75Qj1k1FHi',  # Replace with actual client secret
    server_metadata_url=CONF_URL,
    client_kwargs={'scope': 'openid email profile'}
)

def home(request):
    user = request.session.get('user')
    return render(request, 'home.html', context={'user': json.dumps(user, indent=2) if user else None})

# Login View (Redirects to OAuth Provider)
def sso_login(request):
    redirect_uri = request.build_absolute_uri(reverse('sso_callback'))  # Ensure 'sso_callback' is mapped in urls.py
    state = os.urandom(32).hex()
    nonce = os.urandom(32).hex()
    
    request.session['state'] = state
    request.session['nonce'] = nonce
    
    return oauth.certs_iitb.authorize_redirect(request, redirect_uri, state=state, nonce=nonce)

import requests

def sso_callback(request):
    try:
        # Get access token
        token = oauth.certs_iitb.authorize_access_token(request)
        access_token = token.get('access_token')
        if not access_token:
            return HttpResponse("Failed to get access token from SSO.", status=400)

        print("Access Token:", access_token)  # Debugging

        # Fetch user profile from IITB SSO
        user_info = fetch_user_profile(access_token)
        if not user_info:
            return HttpResponse("Failed to fetch user profile from SSO.", status=400)

        print("User Info from SSO:", json.dumps(user_info, indent=2))  # Debugging

        request.session['user'] = user_info
        request.session['email'] = user_info.get('mail', '')

        # Extract and print DN for debugging
        dn_string = user_info.get("dn", "")
        print("Raw DN String:", dn_string)

        # Extract user role
        user_role = get_access_level(dn_string)
        if user_role == "cc_admin":
            request.session['role'] = 'cc_admin'
            return redirect('cc_admin_main_view')
        elif user_role == "website_admin":
            request.session['role'] = 'website_admin'
            return redirect('website_dashboard')
        else:
            return HttpResponse("Access Denied: Unauthorized user", status=403)

    except Exception as e:
        return HttpResponse(f"Authentication error: {e}", status=500)

def fetch_user_profile(access_token):
    """Fetch user details from IITB SSO using the access token."""
    try:
        user_info_url = "https://sso-uat.iitb.ac.in/user"
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(user_info_url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            print("Failed to fetch user profile. Status Code:", response.status_code)
            return None

    except Exception as e:
        print("Error fetching user profile:", e)
        return None

def get_access_level(dn_string):
    """Extracts 'ou' values from DN and determines user role."""
    print("Raw DN String:", dn_string)  # Debugging

    if not dn_string:
        return None

    dn_parts = [part.strip() for part in dn_string.split(",")]
    ou_values = {part.split("=")[1] for part in dn_parts if part.startswith("ou=")}

    print("Extracted OU values:", ou_values)  # Debugging

    # Determine access level
    if "CC" in ou_values and "People" in ou_values:
        return "cc_admin"
    elif "People" in ou_values:
        return "website_admin"
    else:
        return None  # Access Denied

# Logout View (Clears Session and Logs User Out)
def logout(request):
    request.session.flush()
    return redirect('home')

# CC Admin Dashboard View
def cc_admin_dashboard(request):
    certificates = Certificate.objects.all()
    
    for cert in certificates:
        try:
            # Ensure expiry_date is extracted and saved
            expiry_date = cert.extract_expiry_date()
            if expiry_date:
                cert.expiry_date = expiry_date
                cert.save()
        except Exception as e:
            print(f"Failed to extract expiry date for {cert.domain_name}: {e}")
        
        if cert.expiry_date:
            days_to_expiry = (cert.expiry_date - now().date()).days
            cert.expiry_color = (
                "green" if days_to_expiry > 30 else
                "yellow" if 15 <= days_to_expiry <= 30 else
                "orange" if 7 <= days_to_expiry < 15 else
                "red"
            )
        else:
            cert.expiry_color = "red"
    
    return render(request, "cc_admin_dashboard.html", {"certificates": certificates})

# Website Admin Dashboard View
def website_admin_dashboard(request):
    if request.session.get('role') != 'website_admin':
        return redirect('home')

    admin_email = request.session.get('email')
    certificates = Certificate.objects.filter(owner_email=admin_email).order_by('expiry_date')

    for cert in certificates:
        if cert.expiry_date:
            days_to_expiry = (cert.expiry_date - now().date()).days
            cert.expiry_color = (
                "green" if days_to_expiry > 30 else
                "yellow" if 15 <= days_to_expiry <= 30 else
                "orange" if 7 <= days_to_expiry < 15 else
                "red"
            )
        else:
            cert.expiry_color = "red"

    return render(request, 'certificates/website_admin_dashboard.html', {'certificates': certificates})


logger = logging.getLogger(__name__)
# Certificate List View
def certificate_list(request):
    search_query = request.GET.get('search', '')  # Match the search input name in your form

    if search_query:
        certificates = Certificate.objects.filter(
            domain_name__icontains=search_query
        ) | Certificate.objects.filter(
            owner_email__icontains=search_query
        )
    else:
        certificates = Certificate.objects.all()

    return render(request, 'cc_admin_dashboard.html', {
        'certificates': certificates,
        'search_query': search_query  # So the form input retains the query
    })


def user_certificates(request, username):
    credentials = load_credentials()
    website_admins = credentials.get('website_admins', [])
    
    # Search for the user by username
    user = next((user for user in website_admins if user['username'] == username), None)

    if not user:
        raise Http404("User not found.")
    
    # Now, use the user object to find and display their certificates
    certificates = Certificate.objects.filter(owner_email=user['email'])
    return render(request, 'certificates/user_certificates.html', {'certificates': certificates})


def certificate_upload(request):
    if request.method == 'POST':
        is_locked = 'confirm_owner' in request.POST
        form = CertificateForm(request.POST, request.FILES, is_locked=is_locked)

        if is_locked:
            user_email = request.user.email
            form.fields['owner_email'].initial = user_email

        if form.is_valid():
            certificate = form.save(commit=False)
            certificate.owner_email = form.cleaned_data['owner_email']
            certificate.save()
            messages.success(request, 'Certificate uploaded successfully!')
            return redirect('certificate_list')
        else:
            messages.error(request, "Invalid form submission. Please fix the errors below.")
    else:
        form = CertificateForm()

    # Pass the logged-in user's email to the template
    return render(request, 'certificates/certificate_upload.html', {'form': form, 'user_email': request.user.email})


def download_file(request, certificate_id, file_type):
    try:
        certificate = get_object_or_404(Certificate, id=certificate_id)
        
        # Mapping file types to model fields
        file_map = {
            "certificate": certificate.certificate,
            "private_key": certificate.private_key,
            "csr": certificate.csr
        }
        
        if file_type not in file_map or not file_map[file_type]:
            raise Http404("File not found or not associated with this certificate.")
        
        file_path = file_map[file_type].path
        
        if not os.path.exists(file_path):
            logger.warning(f"Attempted to download non-existent file: {file_path}")
            raise Http404("Requested file does not exist.")

        return FileResponse(
            open(file_path, 'rb'), 
            as_attachment=True, 
            filename=os.path.basename(file_path)
        )
    except Http404:
        raise
    except Exception as e:
        logger.error(f"File download error: {str(e)}")
        messages.error(request, f"An error occurred: {str(e)}")
        return redirect('certificate_list')


def certificate_delete(request, certificate_id):
    certificate = get_object_or_404(Certificate, id=certificate_id)
    certificate.delete()
    messages.success(request, "Certificate deleted successfully.")
    return redirect('certificate_list')  # Replace with the name of your certificate list view


# Certificate Renewal View
def certificate_renew(request, certificate_id):
    certificate = get_object_or_404(Certificate, id=certificate_id)
    if request.method == 'POST':
        form = CertificateRenewalForm(request.POST, request.FILES, instance=certificate)
        if form.is_valid():
            try:
                renewal = form.save()

                # Removed validation for private_key and certificate
                messages.success(request, 'Certificate renewed successfully!')
                return redirect('certificate_list')
            except ValidationError as e:
                messages.error(request, f"Validation error: {e}")
            except Exception as e:
                messages.error(request, f"Unexpected error: {str(e)}")
        else:
            messages.error(request, "Invalid form submission. Please correct the errors.")
    else:
        form = CertificateRenewalForm(instance=certificate)
    return render(request, 'certificates/certificate_renew.html', {'form': form, 'certificate': certificate})


# Certificate Detail View
def certificate_detail(request, certificate_id):
    certificate = get_object_or_404(Certificate, id=certificate_id)
    return render(request, 'certificates/certificate_detail.html', {'certificate': certificate})



def some_view(request):
    # Redirect to the previous page
    referer = request.META.get('HTTP_REFERER')
    if referer:
        return redirect(referer)
    else:
        # Fallback in case there's no referer
        return redirect('default_page_name')

# Load the credentials file
def load_credentials():
    credentials_path = os.path.join(
        os.path.dirname(__file__), 'data', 'credentials.json'
    )
    with open(credentials_path) as f:
        return json.load(f)

# Save the credentials file
def save_credentials(data):
    try:
        credentials_path = os.path.join(
            os.path.dirname(__file__), 'data', 'credentials.json'
        )
        os.makedirs(os.path.dirname(credentials_path), exist_ok=True)  # Ensure directory exists

        # Saving the credentials to the file
        with open(credentials_path, 'w') as file:
            json.dump(data, file, indent=4)

        print(f"Credentials saved successfully to {credentials_path}")
    except Exception as e:
        print(f"Error saving credentials: {e}")

# CC Admin - View and manage users
def cc_admin_users(request):
    credentials = load_credentials()
    users = credentials.get('website_admins', [])

    # Get the search query from request parameters
    search_query = request.GET.get('search', '')

    # Filter users based on username or email containing the search query
    if search_query:
        users = [user for user in users if search_query.lower() in user['username'].lower() or search_query.lower() in user['email'].lower()]

    return render(request, 'cc_admin_users.html', {'users': users, 'search_query': search_query})


def add_user(request):
    print("Add user view triggered!")

    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        role = request.POST['role']

        print(f"Received data: {username}, {email}, {role}") 
        # Load current credentials data
        credentials = load_credentials()

        # Check if the username already exists in either list
        website_admins = credentials.get('website_admins', [])
        cc_admins = credentials.get('cc_admin', {})
        all_users = website_admins + ([cc_admins] if isinstance(cc_admins, dict) else [])

        if any(user['username'] == username for user in all_users):
            messages.error(request, 'Username already exists!')
            return redirect('cc_admin_users')

        # Create new user
        new_user = {
            'username': username,
            'email': email,
            'password': password,  # Save the hashed password
            'role': role,
        }

        # Append user to the appropriate list based on role
        if role == 'website_admin':
            credentials['website_admins'].append(new_user)
        else:
            # Replace the existing `cc_admin` record with the new user (if role is cc_admin)
            credentials['cc_admin'].append(new_user)

        # Save the updated credentials file
        save_credentials(credentials)

        messages.success(request, f'User {username} added successfully!')
        return redirect('cc_admin_users')

    return render(request, 'cc_admin_users.html')


# Edit an existing user's details
def edit_user(request, username):
    credentials = load_credentials()
    
    # Fetch both website_admins and cc_admin for user lookup
    website_admins = credentials.get('website_admins', [])
    cc_admin = credentials.get('cc_admin', {})

    # Find the user by username in both lists
    user_to_edit = next(
        (user for user in website_admins if user['username'] == username), None
    )
    
    is_website_admin = True  # Track if the user is in website_admins
    if not user_to_edit and cc_admin.get('username') == username:
        user_to_edit = cc_admin
        is_website_admin = False

    # If the user is not found in either list
    if not user_to_edit:
        messages.error(request, 'User not found!')
        return redirect('cc_admin_users')

    if request.method == 'POST':
        # Safely fetch POST data using get() with default values
        new_username = request.POST.get('username', user_to_edit['username'])
        new_email = request.POST.get('email', user_to_edit['email'])
        new_password = request.POST.get('password', user_to_edit['password'])
        new_role = request.POST.get('role', user_to_edit['role'])

        # Update user data
        user_to_edit['username'] = new_username
        user_to_edit['email'] = new_email
        user_to_edit['password'] = new_password
        user_to_edit['role'] = new_role

        # If the role is changed, move the user between lists
        if is_website_admin and user_to_edit['role'] != 'website_admin':
            # Remove from website_admins and assign to cc_admin
            website_admins.remove(user_to_edit)
            credentials['cc_admin'] = user_to_edit
        elif not is_website_admin and user_to_edit['role'] == 'website_admin':
            # Remove from cc_admin and append to website_admins
            credentials['cc_admin'] = {}  # Clear cc_admin
            website_admins.append(user_to_edit)

        # Save the updated credentials file
        credentials['website_admins'] = website_admins
        save_credentials(credentials)

        messages.success(request, 'User updated successfully!')
        return redirect('cc_admin_users')

    # Pre-populate the form with existing user data
    return render(request, 'edit_user.html', {'user': user_to_edit})


def cc_admin_main_view(request):
    # Logic for the view
    return render(request, 'cc_admin_main.html')


def delete_user(request, username):
    # Load credentials
    credentials = load_credentials()

    # Remove the user from `website_admins`
    initial_website_admins_count = len(credentials.get('website_admins', []))
    credentials['website_admins'] = [
        user for user in credentials.get('website_admins', [])
        if user['username'] != username
    ]

    # Remove the user from `cc_admin` if they match
    if isinstance(credentials.get('cc_admin'), dict) and credentials['cc_admin'].get('username') == username:
        credentials['cc_admin'] = {}

    # Check if any user was removed
    final_website_admins_count = len(credentials['website_admins'])
    user_removed = initial_website_admins_count > final_website_admins_count or not credentials.get('cc_admin')

    # Save updated credentials
    update_credentials_file(credentials)

    # Provide feedback
    if user_removed:
        messages.success(request, f"User {username} deleted successfully.")
    else:
        messages.error(request, f"User {username} not found.")

    return redirect('cc_admin_users')
