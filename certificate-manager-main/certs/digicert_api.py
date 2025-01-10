import requests
from django.conf import settings

# Separate API functions and sample fallback logic
def fetch_certificate_from_digicert(cert_id, api_key=None):
    """
    Fetches a specific certificate from DigiCert API.
    """
    if not api_key:
        raise ValueError("API key is required to interact with DigiCert API.")
    
    url = f"https://www.digicert.com/services/v2/certificates/{cert_id}"
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }

    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()  # Returns the certificate details


def get_sample_certificate(cert_id):
    """
    Returns a sample certificate when API is unavailable.
    """
    sample_certificates = {
        "sample_cert_1": {
            "domain_name": "example.com",
            "owner": "owner@example.com",
            "expiry_date": "2025-01-01",
            "certificate_data": "sample_certificate_data_here",
            "private_key": "sample_private_key_here"
        }
    }
    return sample_certificates.get(cert_id, {
        "error": "Sample certificate not found for given ID."
    })


# DigiCertAPI Class - Encapsulating DigiCert API operations
class DigiCertAPI:
    base_url = settings.DIGICERT_BASE_URL
    api_key = settings.DIGICERT_API_KEY

    @staticmethod
    def get_headers():
        """
        Returns the authorization headers for DigiCert API requests.
        """
        if not DigiCertAPI.api_key:
            raise ValueError("API key is not configured in settings.")
        return {"Authorization": f"Bearer {DigiCertAPI.api_key}"}

    @staticmethod
    def fetch_certificates():
        """
        Fetches all certificates from DigiCert API.
        """
        url = f"{DigiCertAPI.base_url}/certificates"
        response = requests.get(url, headers=DigiCertAPI.get_headers())
        response.raise_for_status()
        return response.json().get("certificates", [])

    @staticmethod
    def fetch_certificate_details(cert_id):
        """
        Fetches details of a specific certificate by its ID.
        """
        url = f"{DigiCertAPI.base_url}/certificates/{cert_id}"
        response = requests.get(url, headers=DigiCertAPI.get_headers())
        response.raise_for_status()
        return response.json()

    @staticmethod
    def upload_certificate(csr, product_id, validity_years):
        """
        Uploads a new certificate to DigiCert.
        """
        url = f"{DigiCertAPI.base_url}/certificates"
        payload = {
            "certificate": {
                "csr": csr,
                "product": product_id,
                "validity_years": validity_years,
                # Add other required fields
            }
        }
        response = requests.post(url, headers=DigiCertAPI.get_headers(), json=payload)
        response.raise_for_status()
        return response.json()

    @staticmethod
    def renew_certificate(cert_id, csr):
        """
        Renews an existing certificate by its ID.
        """
        url = f"{DigiCertAPI.base_url}/certificates/{cert_id}/renew"
        payload = {"csr": csr}
        response = requests.post(url, headers=DigiCertAPI.get_headers(), json=payload)
        response.raise_for_status()
        return response.json()
