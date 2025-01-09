from django.shortcuts import render, redirect, get_object_or_404
from .models import Certificate, CertificateRenewal
from .forms import CertificateForm, CertificateRenewalForm
from django.contrib import messages
from .digicert_api import DigiCertAPI
from django.conf import settings
from datetime import datetime
import json
import os

USE_DIGICERT_API = settings.USE_DIGICERT_API

# Certificate List View
def certificate_list(request):
    if USE_DIGICERT_API:
        try:
            certificates = DigiCertAPI.fetch_certificates()
        except Exception as e:
            messages.error(request, f"Error fetching certificates from DigiCert: {str(e)}")
            certificates = []
    else:
        certificates = Certificate.objects.all()
    return render(request, 'certificates/certificate_list.html', {'certificates': certificates})

# views.py (certificate_upload function)

def certificate_upload(request):
    if request.method == 'POST':
        form = CertificateForm(request.POST, request.FILES)
        if form.is_valid():
            # Link certificate to admin's email
            certificate = form.save(commit=False)
            certificate.owner_email = request.session.get('email')  # Link to the admin's email
            certificate.save()
            messages.success(request, 'Certificate uploaded successfully!')

            # Redirect based on the role
            role = request.session.get('role')
            if role == 'cc_admin':
                return redirect('cc_admin_dashboard')
            elif role == 'website_admin':
                return redirect('website_admin_dashboard')
            else:
                messages.error(request, "You are not authorized to upload certificates.")
                return redirect('login_page')
        else:
            messages.error(request, "There was an error uploading the certificate. Please check the fields.")
            print(form.errors)  # Debugging line
    else:
        form = CertificateForm()
    return render(request, 'certificates/certificate_upload.html', {'form': form})

# Certificate Renewal View
def certificate_renew(request, certificate_id):
    certificate = get_object_or_404(Certificate, id=certificate_id)
    renewal, created = CertificateRenewal.objects.get_or_create(certificate=certificate)

    if request.method == 'POST':
        form = CertificateRenewalForm(request.POST, request.FILES, instance=renewal)
        if form.is_valid():
            if USE_DIGICERT_API:
                try:
                    csr = form.cleaned_data['csr']
                    DigiCertAPI.renew_certificate(certificate_id, csr)
                    messages.success(request, 'Certificate renewal request processed via DigiCert!')
                except Exception as e:
                    messages.error(request, f"Error renewing certificate: {str(e)}")
            else:
                form.save()
                messages.success(request, 'Certificate renewal request processed!')
            return redirect('certificate_list')
    else:
        form = CertificateRenewalForm(instance=renewal)

    return render(request, 'certificates/certificate_renew.html', {'form': form, 'certificate': certificate})

# Certificate Detail View
def certificate_detail(request, certificate_id):
    certificate_data = None
    files_data = {}

    if USE_DIGICERT_API:
        try:
            certificate_data = DigiCertAPI.fetch_certificate_details(certificate_id)
        except Exception as e:
            messages.error(request, f"Error fetching certificate details from DigiCert: {str(e)}")
    else:
        certificate = get_object_or_404(Certificate, id=certificate_id)
        certificate_data = {
            'id': certificate.id,
            'domain_name': certificate.domain_name,
            'owner': certificate.owner,
            'expiry_date': certificate.expiry_date,
            'notes': certificate.notes,
        }

        files_data = {
            'private_key': str(certificate.private_key).replace('uploads/private_keys/', '') if certificate.private_key else None,
            'certificate': str(certificate.certificate).replace('uploads/certs/', '') if certificate.certificate else None,
        }

    return render(request, 'certificates/certificate_detail.html', {
        'certificate': certificate_data,
        'files': files_data,
    })


def login_page(request):
    # Path to the credentials file
    credentials_file_path = os.path.join(
        os.path.dirname(__file__), 
        'data', 
        'credentials.json'
    )
    
    # Load user credentials from the JSON file
    try:
        with open(credentials_file_path, 'r') as file:
            credentials = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        messages.error(request, "Error loading user credentials. Please contact the administrator.")
        return render(request, 'certificates/login.html')

    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        
        # Check cc_admin credentials
        cc_admin = credentials.get("cc_admin")
        if cc_admin and cc_admin['username'] == username and cc_admin['password'] == password:
            request.session['role'] = cc_admin['role']
            request.session['email'] = cc_admin['email']  # Store email in session
            return redirect('cc_admin_dashboard')
        
        # Check website_admins credentials
        website_admins = credentials.get("website_admins", [])
        for admin in website_admins:
            if admin['username'] == username and admin['password'] == password:
                request.session['role'] = admin['role']
                request.session['email'] = admin['email']  # Store email in session
                return redirect('website_admin_dashboard')

        # If no match found, provide the error message
        messages.error(request, "Invalid credentials. Please try again.")

    return render(request, 'certificates/login.html')


# CC Admin Dashboard View
def cc_admin_dashboard(request):
    if request.session.get('role') != 'cc_admin':
        return redirect('login_page')  # Redirect if not logged in or not the correct role

    # Fetch certificates based on the setting
    if USE_DIGICERT_API:
        try:
            certificates = DigiCertAPI.fetch_certificates()
        except Exception as e:
            messages.error(request, f"Error fetching certificates from DigiCert: {str(e)}")
            certificates = []
    else:
        certificates = Certificate.objects.all().order_by('expiry_date')  # Ascending order
 
        current_date = datetime.now().date()

        # Assign a color class based on the expiry date
        for certificate in certificates:
            # Ensure expiry_date is a date object (if it's a datetime object, convert to date)
            expiry_date = certificate.expiry_date.date() if isinstance(certificate.expiry_date, datetime) else certificate.expiry_date

            # Calculate the number of days left
            days_left = (expiry_date - current_date).days

            # Set expiry color based on the days left
            if days_left > 30:
                certificate.expiry_color = 'green'  # More than 30 days, green
            elif 15 <= days_left <= 30:
                certificate.expiry_color = 'yellow'  # Between 15 and 30 days, yellow
            elif 7 <= days_left < 15:
                certificate.expiry_color = 'orange'  # Between 7 and 15 days, orange
            else:
                certificate.expiry_color = 'red'  # Less than 7 days, red

    return render(request, 'cc_admin_dashboard.html', {'certificates': certificates})

# views.py (website_admin_dashboard function)

def website_admin_dashboard(request):
    # Ensure user is logged in and has the correct role
    if request.session.get('role') != 'website_admin':
        return redirect('login_page')  # Redirect if not logged in or not the correct role

    # Get the admin's email from the session
    admin_email = request.session.get('email')

    # Fetch only the certificates linked to this admin's email
    if USE_DIGICERT_API:
        try:
            certificates = DigiCertAPI.fetch_certificates()
            certificates = [cert for cert in certificates if cert.owner_email == admin_email]
        except Exception as e:
            messages.error(request, f"Error fetching certificates from DigiCert: {str(e)}")
            certificates = []
    else:
        certificates = Certificate.objects.filter(owner_email=admin_email).order_by('expiry_date')  # Filter by admin's email

        current_date = datetime.now().date()

        # Assign a color class based on the expiry date
        for certificate in certificates:
            # Ensure expiry_date is a date object (if it's a datetime object, convert to date)
            expiry_date = certificate.expiry_date.date() if isinstance(certificate.expiry_date, datetime) else certificate.expiry_date

            # Calculate the number of days left
            days_left = (expiry_date - current_date).days

            # Set expiry color based on the days left
            if days_left > 30:
                certificate.expiry_color = 'green'  # More than 30 days, green
            elif 15 <= days_left <= 30:
                certificate.expiry_color = 'yellow'  # Between 15 and 30 days, yellow
            elif 7 <= days_left < 15:
                certificate.expiry_color = 'orange'  # Between 7 and 15 days, orange
            else:
                certificate.expiry_color = 'red'  # Less than 7 days, red

    return render(request, 'website_admin_dashboard.html', {'certificates': certificates})
