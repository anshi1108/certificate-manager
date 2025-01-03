from django.shortcuts import render, redirect, get_object_or_404  # Make sure to import get_object_or_404
from .models import Certificate, CertificateRenewal
from .forms import CertificateForm, CertificateRenewalForm
from django.contrib import messages

def certificate_list(request):
    certificates = Certificate.objects.all()
    return render(request, 'certificates/certificate_list.html', {'certificates': certificates})

# View to upload a new certificate
def certificate_upload(request):
    if request.method == 'POST':
        form = CertificateForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.success(request, 'Certificate uploaded successfully!')
            return redirect('certificate_list')
    else:
        form = CertificateForm()
    return render(request, 'certificates/certificate_upload.html', {'form': form})

# View to renew a certificate
def certificate_renew(request, certificate_id):
    certificate = Certificate.objects.get(id=certificate_id)
    renewal = CertificateRenewal.objects.filter(certificate=certificate).first()

    if request.method == 'POST':
        form = CertificateRenewalForm(request.POST, request.FILES, instance=renewal)
        if form.is_valid():
            form.save()
            messages.success(request, 'Certificate renewal request processed!')
            return redirect('certificate_list')
    else:
        form = CertificateRenewalForm(instance=renewal)

    return render(request, 'certificates/certificate_renew.html', {'form': form, 'certificate': certificate})

def certificate_detail(request, certificate_id):
    # Fetch the certificate object using the provided ID
    certificate = get_object_or_404(Certificate, id=certificate_id)
    return render(request, 'certificates/certificate_detail.html', {'certificate': certificate})
