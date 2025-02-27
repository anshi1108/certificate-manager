import json
import os

# Define the path to the credentials.json file
CREDENTIALS_FILE = os.path.join(os.path.dirname(__file__), 'data', 'credentials.json')

def load_credentials():
    """Load credentials from the credentials.json file."""
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, 'r') as file:
            credentials = json.load(file)
            print(f"Loaded credentials: {credentials}")  # Debugging line
            if 'website_admins' not in credentials:
                credentials['website_admins'] = []  # Initialize if missing
            return credentials
    else:
        return {'website_admins': []}

def update_credentials_file(credentials):
    """Update the credentials.json file with new credentials."""
    print(f"Saving credentials: {credentials}")  # Debugging line
    os.makedirs(os.path.dirname(CREDENTIALS_FILE), exist_ok=True)
    with open(CREDENTIALS_FILE, 'w') as file:
        json.dump(credentials, file, indent=4)

