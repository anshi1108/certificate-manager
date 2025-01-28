from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from .models import Certificate, CertificateRenewal
import OpenSSL
from datetime import datetime, date

class CertificateForm(forms.ModelForm):
    domain_name = forms.CharField(max_length=255)
    owner_email = forms.EmailField(required=False)  # Make email optional by default
    private_key = forms.FileField()
    certificate = forms.FileField()
    csr = forms.FileField()
    notes = forms.CharField(widget=forms.Textarea, required=False)
    
    def clean_owner_email(self):
        # Check if 'I'm the Owner' checkbox is not checked (i.e., the email is required)
        if not self.cleaned_data.get('owner_email') and not self.cleaned_data.get('owner_checkbox'):
            raise forms.ValidationError("Owner Email is required if 'I'm the Owner' is not selected.")
        return self.cleaned_data.get('owner_email')
    class Meta:
        model = Certificate
        fields = ['domain_name', 'private_key', 'certificate', 'csr', 'notes', 'owner_email']

    private_key = forms.FileField(required=False)
    certificate = forms.FileField(required=True)
    csr = forms.FileField(required=True)
    notes = forms.CharField(required=False, widget=forms.Textarea)

    def __init__(self, *args, **kwargs):
        is_locked = kwargs.pop('is_locked', False)
        super().__init__(*args, **kwargs)

        if is_locked:
            self.fields['owner_email'].widget.attrs['readonly'] = True

    def clean_domain_name(self):
        domain_name = self.cleaned_data.get('domain_name')
        if not domain_name:
            raise ValidationError(_("Domain name cannot be empty."))
        return domain_name.replace('.', '_')

    def clean_certificate(self):
        certificate_file = self.cleaned_data.get('certificate')
        if certificate_file:
            try:
                certificate_data = certificate_file.read()
                certificate_file.seek(0)
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate_data)
                not_after = cert.get_notAfter().decode("utf-8")
                expiry_date = datetime.strptime(not_after, "%Y%m%d%H%M%SZ").date()
                if expiry_date < date.today():
                    raise ValidationError(_('The certificate has already expired.'))
            except OpenSSL.crypto.Error as e:
                raise ValidationError(_('Invalid certificate file: %(error)s'), params={'error': str(e)})
        return certificate_file

    def clean_csr(self):
        csr_file = self.cleaned_data.get('csr')
        if csr_file:
            try:
                csr_data = csr_file.read()
                csr_file.seek(0)
                OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr_data)
            except OpenSSL.crypto.Error as e:
                raise ValidationError(_('Invalid CSR file: %(error)s'), params={'error': str(e)})
        return csr_file


class CertificateRenewalForm(forms.ModelForm):
    csr = forms.FileField(required=False)

    class Meta:
        model = CertificateRenewal
        fields = ['certificate', 'request_complete', 'csr']

    def clean_csr(self):
        csr_file = self.cleaned_data.get('csr')
        if csr_file:
            try:
                # Safely read file content
                csr_data = csr_file.read()
                csr_file.seek(0)  # Reset file pointer
                
                OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr_data)

            except OpenSSL.crypto.Error as e:
                raise ValidationError(_('Invalid CSR file: %(error)s'), params={'error': str(e)})
        return csr_file

    def clean_certificate(self):
        certificate_file = self.cleaned_data.get('certificate')
        if certificate_file:
            try:
                # Safely read file content
                certificate_data = certificate_file.read()
                certificate_file.seek(0)  # Reset file pointer
                
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate_data)

                # Validate expiration date
                not_after = cert.get_notAfter().decode("utf-8")
                expiry_date = datetime.strptime(not_after, "%Y%m%d%H%M%SZ").date()
                if expiry_date < date.today():
                    raise ValidationError(_('The certificate has already expired.'))

            except OpenSSL.crypto.Error as e:
                raise ValidationError(_('Invalid certificate file: %(error)s'), params={'error': str(e)})
        return certificate_file