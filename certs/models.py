import subprocess
from django.db import models
from django.core.exceptions import ValidationError
from datetime import datetime, date
import os

from certificate_manager.settings import BASE_DIR 

def custom_cert_name(instance, filename):
    extension = filename.split('.')[-1]
    modified_domain_name = instance.domain_name.replace(".", "_")
    today = date.today()
    new_filename = f"{modified_domain_name}-{today}.{extension}"
    return f"uploads/certs/{new_filename}"


def custom_key_name(instance, filename):
    extension = filename.split('.')[-1]
    modified_domain_name = instance.domain_name.replace(".", "_")
    today = date.today()
    new_filename = f"{modified_domain_name}-{today}.{extension}"
    return f"uploads/private_keys/{new_filename}"


class Certificate(models.Model):
    domain_name = models.CharField(max_length=255, blank=False, null=False)
    owner = models.EmailField(blank=False, null=False)
    expiry_date = models.DateTimeField(null=True, blank=True)
    notes = models.CharField(max_length=1000, blank=True, null=True)
    archived = models.BooleanField(default=False)
    private_key = models.FileField(upload_to=custom_key_name)
    certificate = models.FileField(upload_to=custom_cert_name)

    def __str__(self):
        return self.domain_name

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)   
        if not self.validate_private_key_and_cert():
            raise ValidationError("Certificate validation failed.")
        self.expiry_date = self.extract_cert_expiry()
        super().save(*args, **kwargs)

    def validate_private_key_and_cert(self):
        try:
            validation_output = subprocess.check_output([
                'openssl', 'x509', '-noout', '-in', self.certificate.path,
                '-pubkey', '-out', '/dev/null', '-signkey', self.private_key.path
            ])
            return not validation_output            
        except subprocess.CalledProcessError:
            return False
    
    def extract_cert_expiry(self):
        cert_info = subprocess.check_output([
            'openssl', 'x509', '-noout', '-enddate', '-in', self.certificate.path
        ]).decode('utf-8')
        expiry_date_str = cert_info.split('=')[1].strip()
        print(f"Extracted Expiry Date: {expiry_date_str}")  # Debugging line
        return datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z')



class CertificateRenewal(models.Model):
    certificate = models.ForeignKey(Certificate, on_delete=models.CASCADE)
    private_key = models.FileField(upload_to='uploads/renewal_private_keys/', null=True, blank=True)
    certificate_request = models.FileField(upload_to='uploads/renewal_csr_files/', null=True, blank=True)
    renewed_certificate = models.FileField(upload_to='uploads/renewed_certificates/', null=True, blank=True)
    request_complete = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.private_key and not self.certificate_request:
            csr_file_path = os.path.join(BASE_DIR,'uploads/renewal_csr_files/', f'{self.certificate.domain_name}.csr')
            self.generate_csr(csr_file_path)
            self.certificate_request = csr_file_path
            self.private_key = self.certificate.private_key
        if self.private_key and self.certificate_request:
            if not self.validate_private_key_and_csr():
                raise ValidationError("Validation of private key and CSR failed.")

        #TODO: add user validation
        
        if self.renewed_certificate and self.request_complete:
            self.certificate.private_key = self.private_key
            self.certificate.certificate = self.renewed_certificate
            self.certificate.save()

        super().save(*args, **kwargs)
    
    def validate_private_key_and_csr(self):
        try:
            key_hash = subprocess.check_output([
                'openssl', 'rsa', '-noout', '-modulus', '-in', self.private_key.path
            ])
            csr_hash = subprocess.check_output([
                'openssl', 'req', '-noout', '-modulus', '-in', self.certificate_request.path
            ])
            print(key_hash)
            print(csr_hash)
            return key_hash == csr_hash
        except subprocess.CalledProcessError:
            return False
    
    def generate_csr(self, csr_file_path):
        generate_csr_command = [
                'openssl', 'x509', '-x509toreq', '-in', self.certificate.certificate.path, '-signkey', self.certificate.private_key.path, '-out', csr_file_path
            ]
        try:
            subprocess.run(generate_csr_command)
        except subprocess.CalledProcessError:
            raise ValidationError("Unable to generate CSR")