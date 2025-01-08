from django.shortcuts import render, redirect, get_object_or_404
from .models import Certificate, CertificateRenewal
from .forms import CertificateForm, CertificateRenewalForm
from django.contrib import messages
from .digicert_api import DigiCertAPI
from django.conf import settings

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

# Certificate Upload View
def certificate_upload(request):
    if request.method == 'POST':
        form = CertificateForm(request.POST, request.FILES)
        if form.is_valid():
            if USE_DIGICERT_API:
                try:
                    csr = form.cleaned_data['csr']
                    product_id = form.cleaned_data['product_id']
                    validity_years = form.cleaned_data['validity_years']
                    DigiCertAPI.upload_certificate(csr, product_id, validity_years)
                    messages.success(request, 'Certificate uploaded successfully to DigiCert!')
                except Exception as e:
                    messages.error(request, f"Error uploading certificate to DigiCert: {str(e)}")
            else:
                form.save()
                messages.success(request, 'Certificate uploaded successfully!')
            return redirect('certificate_list')
        else:
            messages.error(request, "There was an error uploading the certificate. Please check the fields.")
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

# Hardcoded credentials (for demo purposes)
USER_CREDENTIALS = {
    'abc': {'password': 'password1', 'role': 'website_admin'},
    'xyz': {'password': 'password2', 'role': 'cc_admin'},
}

# Login Page View
def login_page(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        
        # Check if the user exists and the password matches
        user = USER_CREDENTIALS.get(username)
        if user and user['password'] == password:
            # Store the user role in the session
            request.session['role'] = user['role']
            # Redirect based on the role
            if user['role'] == 'cc_admin':
                return redirect('cc_admin_dashboard')
            elif user['role'] == 'website_admin':
                return redirect('website_admin_dashboard')
        else:
            messages.error(request, "Invalid credentials!")
    
    return render(request, 'certificates/login.html')

# CC Admin Dashboard View
def cc_admin_dashboard(request):
    # Ensure user is logged in and has the correct role
    if request.session.get('role') != 'cc_admin':
        return redirect('login_page')  # Redirect if not logged in or not the correct role
    return render(request, 'cc_admin_dashboard.html')

# Website Admin Dashboard View
def website_admin_dashboard(request):
    # Ensure user is logged in and has the correct role
    if request.session.get('role') != 'website_admin':
        return redirect('login_page')  # Redirect if not logged in or not the correct role
    return render(request, 'website_admin_dashboard.html')
