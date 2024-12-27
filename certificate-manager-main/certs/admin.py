from django.contrib import admin
from .models import Certificate, CertificateRenewal
# Register your models here.
class CertificateModelAdmin(admin.ModelAdmin):
    list_display = ('domain_name', 'owner', 'expiry_date')
    search_fields = ('domain_name', 'owner')
    list_filter = ('owner',)
class RenewalAdmin(admin.ModelAdmin):
    list_display = ('certificate', 'request_complete')
    list_filter = ('certificate',)
    search_fields = ('certificate__domain_name',)


admin.site.register(Certificate, CertificateModelAdmin)
admin.site.register(CertificateRenewal, RenewalAdmin)