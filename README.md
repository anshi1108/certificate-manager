***SSL Certificate Management System***

**Hosted on:** [cert.iitb.ac.in](https://cert.iitb.ac.in)

**How to run this file:**
After downloading a Django project from GitHub, you need to set it up properly before running the development server. Here's how to do it:

1. Clone the Repository:
   git clone https://github.com/anshi1108/certificate-manager.git
   OR download the zip file

2. Navigate to the Project Directory:

3. Create and Activate a Virtual Environment:
   This sets up an isolated environment for your project's dependencies.

4. Install Dependencies:
   >pip install -r requirements.txt

5. Apply Migrations:
   >python manage.py migrate
   This sets up your database schema.

6. Create a Superuser (Optional):
   >python manage.py createsuperuser
   This allows you to access the Django admin interface.

7. Collect Static Files:
   >python manage.py collectstatic

8. Run the Development Server:
   >python manage.py runserver
   Your application should now be accessible at `http://127.0.0.1:8000/`.
   If you want it to be accessible by other devices on a bridged network, run it using:
   >python manage.py runserver 0.0.0.0:8000

**How to login once it is setup**
The system is integrated with IITB SSO authentication. Login credentials for testing CC Admin and Website Admin roles can be found in the "credentials.json" file located in:
   certs/data/credentials.json

**What does this software do?**
This project is a centralized SSL Certificate Management System that allows:
- Secure login via IITB SSO.
- Role-based access control for CC Admins and Website Admins.
- Secure certificate and private key storage based on domain names.
- Viewing, searching, and managing certificates.
- Downloading CSR, CRT, and private keys.
- Automatic extraction of certificate expiry dates using OpenSSL.
- OpenSSL-based validation and verification during upload.

**Role-Based Access Control:**
- **CC Admin:**
  - View and manage all certificates and users.
  - Edit user details.
  - Upload certificates for any user.
- **Website Admin:**
  - View only their own certificates.
  - Upload certificates linked to their own email.

**Recently added features:**
1. Front page with role-based login and permissions using IITB SSO authentication.
2. CC Admin dashboard with search, sorting, and filtering for managing users and certificates.
3. Website Admin dashboard to view and manage only their certificates.
4. Integration of OpenSSL for automated expiry date extraction and validation.
5. Secure centralized storage for certificates and private keys.
6. Hosted on **cert.iitb.ac.in** and linked to IITB SSO.

**Future Implementation:**
1. Integration of DigiCert and GlobalSign API to automate the process.
2. Advanced filtering system for classifying and maintaining certificates.
3. Self-renewal functionality based on certificate type (wildcard/non-wildcard).
4. Categorization based on approved subdomains.
5. Traffic control options for global or local access.
6. In-form generation of key and certificate for users who do not have them.

This system enhances security, streamlines certificate management, and ensures compliance with SSL best practices.

