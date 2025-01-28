import os
import subprocess
import logging
from django.db import models
from django.core.exceptions import ValidationError
from datetime import datetime, date
import OpenSSL

# Configure logging
logger = logging.getLogger(__name__)

def custom_file_name(instance, filename, file_type):
    """
    Generates a custom file name for uploads.
    """
    extension = filename.split('.')[-1]
    modified_domain_name = instance.domain_name.replace(".", "_")
    today = date.today()
    return f"uploads/{file_type}/{modified_domain_name}-{today}.{extension}"

class Certificate(models.Model):
    # Existing fields remain the same
    domain_name = models.CharField(max_length=255)
    owner_email = models.EmailField()
    private_key = models.FileField(
        upload_to=lambda instance, filename: custom_file_name(instance, filename, 'private_keys'), 
        blank=True, 
        null=True
    )
    certificate = models.FileField(
        upload_to=lambda instance, filename: custom_file_name(instance, filename, 'certs'), 
        blank=True, 
        null=True
    )
    csr = models.FileField(
        upload_to=lambda instance, filename: custom_file_name(instance, filename, 'csrs'), 
        blank=True, 
        null=True
    )
    notes = models.TextField(blank=True, null=True)
    expiry_date = models.DateField(null=True, blank=True)
    def str(self):
        return self.domain_name
    def save(self, *args, **kwargs):
        """
        Enhanced save logic to handle expiry date extraction more robustly.
        """
        try:
            # Only extract expiry date if certificate exists and expiry_date is not already set
            if self.certificate and not self.expiry_date:
                self.expiry_date = self.extract_expiry_date()
        except Exception as e:
            logger.error(f"Error extracting expiry date: {str(e)}")
            # Optionally set a default or error state
            self.expiry_date = None
        
        super().save(*args, **kwargs)

    def extract_expiry_date(self):
        """
        Improved expiry date extraction with more error handling.
        """
        if not self.certificate:
            logger.warning(f"No certificate file for {self.domain_name}")
            return None

        try:
            cert_path = self.certificate.path
            
            # Additional file existence and readability checks
            if not os.path.exists(cert_path):
                logger.error(f"Certificate file not found: {cert_path}")
                return None

            # Use context manager for file handling
            with open(cert_path, 'rb') as cert_file:
                cert_data = cert_file.read()

            # Parse certificate
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_data)

            # Extract and convert expiry date
            not_after = cert.get_notAfter().decode("utf-8")
            expiry_date = datetime.strptime(not_after, "%Y%m%d%H%M%SZ").date()

            logger.info(f"Certificate for {self.domain_name} expires on {expiry_date}")
            return expiry_date

        except Exception as e:
            logger.error(f"Detailed expiry date extraction error for {self.domain_name}: {str(e)}")
            return None
        
        
class CertificateRenewal(models.Model):
    certificate = models.ForeignKey(Certificate, on_delete=models.CASCADE)
    request_complete = models.BooleanField(default=False)
    renewal_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Renewal for {self.certificate.domain_name}"