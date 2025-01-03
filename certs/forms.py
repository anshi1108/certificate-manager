from django import forms
from .models import Certificate
from .models import CertificateRenewal
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

# Custom Date Input to ensure proper format
class DateInput(forms.DateInput):
    input_type = 'date'

# Form for uploading a certificate
class CertificateForm(forms.ModelForm):
    class Meta:
        model = Certificate
        fields = ['domain_name', 'owner', 'private_key', 'certificate', 'notes', 'expiry_date']
        widgets = {
            'expiry_date': DateInput(),
        }

    # Making all fields required explicitly
    domain_name = forms.CharField(required=True)
    owner = forms.CharField(required=True)
    private_key = forms.FileField(required=True)
    certificate = forms.FileField(required=True)
    notes = forms.CharField(required=True, widget=forms.Textarea)
    expiry_date = forms.DateField(required=True, widget=DateInput)

    # Validating expiry_date format
    def clean_expiry_date(self):
        expiry_date = self.cleaned_data.get('expiry_date')
        # Ensure date is in proper format (this will use the date input widget for proper validation)
        if not expiry_date:
            raise ValidationError(_("Please provide a valid expiry date in the correct format."))
        return expiry_date

class CertificateRenewalForm(forms.ModelForm):
    class Meta:
        model = CertificateRenewal
        fields = ['private_key', 'certificate_request', 'renewed_certificate', 'request_complete']
