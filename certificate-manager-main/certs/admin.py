from django.contrib import admin
from .models import Certificate, CertificateRenewal

# Register your models here.
class CertificateModelAdmin(admin.ModelAdmin):
    list_display = ('domain_name', 'owner', 'owner_email', 'expiry_date')  # Added owner_email
    search_fields = ('domain_name', 'owner', 'owner_email')  # Added owner_email
    list_filter = ('owner', 'owner_email', 'expiry_date')  # Added owner_email
    date_hierarchy = 'expiry_date'


class RenewalAdmin(admin.ModelAdmin):
    list_display = ('certificate', 'get_domain_name', 'request_complete')
    list_filter = ('certificate', 'request_complete')
    search_fields = ('certificate__domain_name',)

    def get_domain_name(self, obj):
        return obj.certificate.domain_name
    get_domain_name.short_description = 'Domain Name'


admin.site.register(Certificate, CertificateModelAdmin)
admin.site.register(CertificateRenewal, RenewalAdmin)
