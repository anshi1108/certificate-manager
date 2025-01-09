***Certificate Renewal System***

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
   if you want it to be accessible by other devices on a bridged network, run it using:
    >python manage.py runserver 0.0.0.0:8000



***What does this software do?***

This project is a form-based system used to renew SSL certificates for a specific domain. The form handles the following inputs and processes:
1. Private Key
   - A file input for uploading the private key for the domain. 
   - Displays the current file if one has been uploaded previously.
   - Validates input and shows error messages if the file is not uploaded or incorrect.
2. Certificate Request
   - A file input for uploading the certificate request for the domain.
   - Displays the current file if one has been uploaded previously.
   - Validates input and shows error messages if the file is not uploaded or incorrect.
3. Renewed Certificate
   - A file input for uploading the renewed certificate for the domain.
   - Displays the current file if one has been uploaded previously.
   - Validates input and shows error messages if the file is not uploaded or incorrect.
4. Request Complete
   - A checkbox for marking whether the certificate renewal request has been completed.


Recently added features:

1. Creating a front page that allows several types of login with role allocation and permission
2. Creating a dashboard that allows admin to view all certificates and users and sort through using several parameters
3. A dashboard for users that lets them view only their certificates and sort them
4. An API mode and a TESTING mode:
- API mode is turned off when api is not connected 
- Testing mode is turned on during testing, it ignores errors like invalid file types for ease of debugging
Both of these can be found in the settings.py 


Future Implementation:

1. Integration of Digi Cert and Global Sign API to automate the process
2. Using a filtering system to classify all the certificates and maintain them by proper storage
3. Self renewal of these based on their type (wildcard/not)
4. Categorising them based on approved subdomain/not
5. Allowing global or local traffic to them based on the requirement of the specific website
6. Give an option to generate key and certificate right there in the form if they dont have that already
