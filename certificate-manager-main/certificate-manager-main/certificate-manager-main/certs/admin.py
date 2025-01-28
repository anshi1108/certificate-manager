from django.contrib import admin
from .models import Certificate, CertificateRenewal
from django.core.exceptions import ValidationError

# Admin for Certificate model
@admin.register(Certificate)
class CertificateModelAdmin(admin.ModelAdmin):
    """
    Admin interface for managing Certificates.
    """
    list_display = ('domain_name', 'owner_email', 'get_expiry_date')  # Columns to display
    search_fields = ('domain_name', 'owner_email')  # Enable search by domain name and owner email
    list_filter = ('owner_email',)  # Filter by owner email
    date_hierarchy = None  # Removed expiry_date from date_hierarchy

    def get_expiry_date(self, obj):
        """
        Returns the expiry date of the certificate or shows an error if unavailable.
        """
        try:
            # Using extract_expiry_date method to retrieve expiry date
            return obj.extract_expiry_date()
        except ValidationError:
            return "Invalid Certificate"

    get_expiry_date.short_description = "Expiry Date"  # Column label in the admin panel


# Admin for CertificateRenewal model
@admin.register(CertificateRenewal)
class RenewalAdmin(admin.ModelAdmin):
    """
    Admin interface for managing Certificate Renewals.
    """
    list_display = ('certificate', 'get_domain_name', 'request_complete')  # Columns to display
    list_filter = ('request_complete',)  # Filter by request status
    search_fields = ('certificate__domain_name',)  # Enable search by certificate domain name

    def get_domain_name(self, obj):
        """
        Fetches the domain name of the associated certificate.
        """
        return obj.certificate.domain_name

    get_domain_name.short_description = 'Domain Name'  # Column label in the admin panel
