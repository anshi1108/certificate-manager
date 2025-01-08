from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from .models import Certificate, CertificateRenewal
import subprocess
import tempfile
import os

# Validators
def validate_certificate(file):
    """
    Validates the uploaded certificate file using OpenSSL.
    """
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(file.read())
        temp_file_path = temp_file.name

    try:
        subprocess.check_output(['openssl', 'x509', '-noout', '-in', temp_file_path])
    except subprocess.CalledProcessError:
        raise ValidationError("Invalid certificate file.")
    finally:
        os.remove(temp_file_path)


def validate_private_key(file):
    """
    Validates the uploaded private key file using OpenSSL.
    """
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(file.read())
        temp_file_path = temp_file.name

    try:
        subprocess.check_output(['openssl', 'rsa', '-noout', '-in', temp_file_path])
    except subprocess.CalledProcessError:
        raise ValidationError('Invalid private key file.')
    finally:
        os.remove(temp_file_path)


# Custom Date Input widget
class DateInput(forms.DateInput):
    input_type = 'date'


# Certificate Form
class CertificateForm(forms.ModelForm):
    """
    Form for uploading and validating certificate data.
    """
    class Meta:
        model = Certificate
        fields = ['domain_name', 'owner', 'private_key', 'certificate', 'notes', 'expiry_date']
        widgets = {
            'expiry_date': DateInput(),
        }

    domain_name = forms.CharField(required=True)
    owner = forms.CharField(required=True)
    private_key = forms.FileField(required=True, validators=[validate_private_key])
    certificate = forms.FileField(required=True, validators=[validate_certificate])
    notes = forms.CharField(required=False, widget=forms.Textarea)
    expiry_date = forms.DateField(required=True, widget=DateInput)

    def clean_expiry_date(self):
        """
        Validates the expiry date format.
        """
        expiry_date = self.cleaned_data.get('expiry_date')
        if not expiry_date:
            raise ValidationError(_("Please provide a valid expiry date."))
        return expiry_date

    def clean_domain_name(self):
        """
        Ensures the domain name is unique.
        """
        domain_name = self.cleaned_data.get('domain_name')
        if Certificate.objects.filter(domain_name=domain_name).exists():
            raise ValidationError(_("A certificate for this domain already exists."))
        return domain_name


# Certificate Renewal Form
class CertificateRenewalForm(forms.ModelForm):
    """
    Form for renewing certificates.
    """
    csr = forms.CharField(widget=forms.Textarea, required=True)

    class Meta:
        model = CertificateRenewal
        fields = ['csr', 'private_key', 'certificate_request', 'renewed_certificate', 'request_complete']
        widgets = {
            'csr': forms.Textarea(attrs={'rows': 4}),
        }
