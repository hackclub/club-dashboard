"""
Hack Club Identity Service for OAuth authentication
"""
import os
import urllib.parse
import requests

# This will be properly initialized when imported by the app
app = None
HACKCLUB_IDENTITY_URL = None
HACKCLUB_IDENTITY_CLIENT_ID = None
HACKCLUB_IDENTITY_CLIENT_SECRET = None


def init_service(flask_app, identity_url, client_id, client_secret):
    """Initialize the service with app context and configuration"""
    global app, HACKCLUB_IDENTITY_URL, HACKCLUB_IDENTITY_CLIENT_ID, HACKCLUB_IDENTITY_CLIENT_SECRET
    app = flask_app
    HACKCLUB_IDENTITY_URL = identity_url
    HACKCLUB_IDENTITY_CLIENT_ID = client_id
    HACKCLUB_IDENTITY_CLIENT_SECRET = client_secret


class HackClubIdentityService:
    def __init__(self):
        self.base_url = HACKCLUB_IDENTITY_URL
        self.client_id = HACKCLUB_IDENTITY_CLIENT_ID
        self.client_secret = HACKCLUB_IDENTITY_CLIENT_SECRET

    def get_auth_url(self, redirect_uri, state=None):
        params = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': 'basic_info address'
        }
        if state:
            params['state'] = state
        return f"{self.base_url}/oauth/authorize?{urllib.parse.urlencode(params)}"

    def exchange_code(self, code, redirect_uri):
        data = {
            'code': code,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'
        }
        try:
            response = requests.post(f'{self.base_url}/oauth/token', json=data)
            return response.json()
        except:
            return {'error': 'Request failed'}

    def get_user_identity(self, access_token):
        headers = {'Authorization': f'Bearer {access_token}'}
        try:
            response = requests.get(f'{self.base_url}/api/v1/me', headers=headers)
            if response.status_code == 200:
                data = response.json()
                app.logger.debug(f"Identity API response: {data}")
                return data
            else:
                app.logger.warning(f"Identity API error: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            app.logger.error(f"Identity API request failed: {str(e)}")
            return None
