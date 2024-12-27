# forms.py
from django import forms
from .models import Certificate, CertificateRenewal

# Form for uploading a certificate
class CertificateForm(forms.ModelForm):
    class Meta:
        model = Certificate
        fields = ['domain_name', 'owner', 'private_key', 'certificate', 'notes']

# Form for certificate renewal
class CertificateRenewalForm(forms.ModelForm):
    class Meta:
        model = CertificateRenewal
        fields = ['private_key', 'certificate_request', 'renewed_certificate', 'request_complete']
