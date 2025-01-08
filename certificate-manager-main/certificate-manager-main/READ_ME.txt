Certificate Renewal System

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


Currently working on:

1. Creating a front page that allows several types of login with role allocation and permission
2. Creating a dashboard that allows admin to view all certificates and users and sort through using several parameters
3. A dashboard for users that lets them view only their certificates and sort them


Future Implementation:

1. Integration of Digi Cert and Global Sign API to automate the process
2. Using a filtering system to classify all the certificates and maintain them by proper storage
3. Self renewal of these based on their type (wildcard/not)
4. Categorising them based on approved subdomain/not
5. Allowing global or local traffic to them based on the requirement of the specific website
