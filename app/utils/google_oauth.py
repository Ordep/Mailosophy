"""
Google OAuth utility for Mailosophy
Handles Google authentication and token management
"""
import os
import re
import requests
from urllib.parse import urlencode, parse_qs, urlparse

class GoogleOAuth:
    def __init__(self):
        self.client_id = os.getenv('GOOGLE_CLIENT_ID')
        self.client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
        self.redirect_uri = os.getenv('GOOGLE_REDIRECT_URI', 'http://localhost:5000/auth/google/callback')
        self.auth_uri = 'https://accounts.google.com/o/oauth2/v2/auth'
        self.token_uri = 'https://oauth2.googleapis.com/token'
        self.userinfo_uri = 'https://www.googleapis.com/oauth2/v2/userinfo'
        self.scopes = [
            'openid',
            'email',
            'profile',
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/gmail.modify',
        ]
    
    def get_authorization_url(self):
        """Get authorization URL for user to sign in"""
        state = os.urandom(32).hex()
        
        params = {
            'client_id': self.client_id,
            'response_type': 'code',
            'scope': ' '.join(self.scopes),
            'redirect_uri': self.redirect_uri,
            'state': state,
            'access_type': 'offline',
            'prompt': 'consent'
        }
        
        authorization_url = f"{self.auth_uri}?{urlencode(params)}"
        return authorization_url, state
    
    def exchange_code_for_token(self, code):
        """Exchange authorization code for access token"""
        try:
            data = {
                'code': code,
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'redirect_uri': self.redirect_uri,
                'grant_type': 'authorization_code'
            }
            
            response = requests.post(self.token_uri, data=data)
            print(f"Token response status: {response.status_code}")
            print(f"Token response: {response.text}")
            
            if response.status_code == 200:
                tokens = response.json()
                # Create a credentials-like object
                class Credentials:
                    def __init__(self, token_data):
                        self.token = token_data.get('access_token')
                        self.refresh_token = token_data.get('refresh_token')
                        self.id_token = token_data.get('id_token')
                
                return Credentials(tokens)
            else:
                print(f"Error exchanging code: {response.text}")
                return None
                
        except Exception as e:
            print(f"Error exchanging code: {e}")
            import traceback
            print(traceback.format_exc())
            return None
    
    def get_user_info(self, credentials):
        """Get user info from Google"""
        try:
            headers = {'Authorization': f'Bearer {credentials.token}'}
            response = requests.get(self.userinfo_uri, headers=headers)
            
            print(f"Userinfo response status: {response.status_code}")
            print(f"Userinfo response: {response.text}")
            
            if response.status_code == 200:
                user_info = response.json()
                return {
                    'id': user_info.get('id'),
                    'email': user_info.get('email'),
                    'name': user_info.get('name'),
                    'picture': user_info.get('picture')
                }
            return None
        except Exception as e:
            print(f"Error getting user info: {e}")
            import traceback
            print(traceback.format_exc())
            return None
    
    def refresh_access_token(self, refresh_token):
        """Refresh access token using refresh token"""
        try:
            data = {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'refresh_token': refresh_token,
                'grant_type': 'refresh_token'
            }
            
            response = requests.post(self.token_uri, data=data)
            if response.status_code == 200:
                return response.json()['access_token']
            return None
        except Exception as e:
            print(f"Error refreshing token: {e}")
            return None


class GmailHelper:
    """Helper for Gmail API operations"""
    API_BASE = 'https://www.googleapis.com/gmail/v1/users/me'
    LABEL_ENDPOINT = f'{API_BASE}/labels'
    _GMAIL_ID_PATTERN = re.compile(r'^[A-Za-z0-9_-]+$')

    @staticmethod
    def get_gmail_service(credentials):
        """Get Gmail service"""
        try:
            from googleapiclient.discovery import build
            return build('gmail', 'v1', credentials=credentials)
        except Exception as e:
            print(f"Error building Gmail service: {e}")
            return None

    @staticmethod
    def get_gmail_labels(access_token):
        """Fetch all Gmail labels using Gmail API"""
        try:
            import requests
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }

            response = requests.get(
                GmailHelper.LABEL_ENDPOINT,
                headers=headers
            )

            if response.status_code == 200:
                labels_data = response.json()
                labels = []

                # Filter out system labels if desired, or keep all
                for label in labels_data.get('labels', []):
                    label_info = {
                        'id': label.get('id'),
                        'name': label.get('name'),
                        'type': label.get('type'),  # 'system' or 'user'
                    }
                    labels.append(label_info)

                return labels
            else:
                print(f"Error fetching Gmail labels: {response.text}")
                return None

        except Exception as e:
            print(f"Error fetching Gmail labels: {e}")
            import traceback
            print(traceback.format_exc())
            return None

    @staticmethod
    def ensure_label(access_token, label_name):
        """Ensure a Gmail label exists and return its ID."""
        labels = GmailHelper.get_gmail_labels(access_token) or []
        for label in labels:
            if label['name'].lower() == label_name.lower():
                return label['id']

        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            payload = {
                'name': label_name,
                'labelListVisibility': 'labelShow',
                'messageListVisibility': 'show'
            }
            response = requests.post(GmailHelper.LABEL_ENDPOINT, headers=headers, json=payload)
            if response.status_code == 200:
                return response.json().get('id')
            else:
                print(f"Error creating Gmail label: {response.text}")
                return None
        except Exception as e:
            print(f"Error ensuring Gmail label: {e}")
            import traceback
            print(traceback.format_exc())
            return None

    @staticmethod
    def find_label_id(access_token, label_name):
        """Find an existing Gmail label ID by name without creating it."""
        labels = GmailHelper.get_gmail_labels(access_token) or []
        for label in labels:
            if label.get('name', '').lower() == label_name.lower():
                return label.get('id')
        return None

    @staticmethod
    def apply_labels_to_message(access_token, rfc822_message_id, label_ids):
        """Apply Gmail label IDs to the message matching the RFC822 message id."""
        if not rfc822_message_id:
            return False

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        try:
            search_params = {'q': f'rfc822msgid:{rfc822_message_id}'}
            search_resp = requests.get(f'{GmailHelper.API_BASE}/messages', headers=headers, params=search_params)
            if search_resp.status_code != 200:
                print(f"Error searching Gmail message: {search_resp.text}")
                return False
            messages = search_resp.json().get('messages', [])
            if not messages:
                print("No Gmail message matched the RFC822 Message-ID")
                return False

            gmail_message_id = messages[0]['id']
            modify_resp = requests.post(
                f'{GmailHelper.API_BASE}/messages/{gmail_message_id}/modify',
                headers=headers,
                json={'addLabelIds': label_ids}
            )
            if modify_resp.status_code == 200:
                return True
            print(f"Error applying Gmail labels: {modify_resp.text}")
            return False
        except Exception as e:
            print(f"Error applying Gmail labels: {e}")
            import traceback
            print(traceback.format_exc())
            return False

    @staticmethod
    def remove_labels_from_message(access_token, rfc822_message_id, label_ids):
        """Remove Gmail label IDs from the message matching the RFC822 Message-ID."""
        if not rfc822_message_id:
            return False

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        try:
            search_params = {'q': f'rfc822msgid:{rfc822_message_id}'}
            search_resp = requests.get(f'{GmailHelper.API_BASE}/messages', headers=headers, params=search_params)
            if search_resp.status_code != 200:
                print(f"Error searching Gmail message: {search_resp.text}")
                return False
            messages = search_resp.json().get('messages', [])
            if not messages:
                print("No Gmail message matched the RFC822 Message-ID for removal")
                return False

            gmail_message_id = messages[0]['id']
            modify_resp = requests.post(
                f'{GmailHelper.API_BASE}/messages/{gmail_message_id}/modify',
                headers=headers,
                json={'removeLabelIds': label_ids}
            )
            if modify_resp.status_code == 200:
                return True
            print(f"Error removing Gmail labels: {modify_resp.text}")
            return False
        except Exception as e:
            print(f"Error removing Gmail labels: {e}")
            import traceback
            print(traceback.format_exc())
            return False

    @staticmethod
    def move_message_to_trash(access_token, rfc822_message_id):
        """Move the Gmail message that matches the RFC822 Message-ID to trash."""
        if not rfc822_message_id:
            return False

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        try:
            search_params = {'q': f'rfc822msgid:{rfc822_message_id}'}
            search_resp = requests.get(
                f'{GmailHelper.API_BASE}/messages',
                headers=headers,
                params=search_params
            )
            gmail_ids = []
            if search_resp.status_code == 200:
                messages = search_resp.json().get('messages', [])
                if messages:
                    gmail_ids.append(messages[0]['id'])
            elif search_resp.status_code not in (400, 404):
                print(f"Error searching Gmail message for trash: {search_resp.text}")

            # Fallback: if stored message id already looks like a Gmail internal id,
            # attempt to trash it directly.
            if not gmail_ids and GmailHelper._GMAIL_ID_PATTERN.fullmatch(rfc822_message_id):
                gmail_ids.append(rfc822_message_id)

            if not gmail_ids:
                # Treat missing Gmail message as already deleted
                return True

            for gmail_message_id in gmail_ids:
                trash_resp = requests.post(
                    f'{GmailHelper.API_BASE}/messages/{gmail_message_id}/trash',
                    headers=headers
                )
                if trash_resp.status_code == 200:
                    return True
                if trash_resp.status_code == 404:
                    # Already gone – that's fine
                    return True
                print(f"Error trashing Gmail message ({gmail_message_id}): {trash_resp.text}")

            return False
        except Exception as e:
            print(f"Error moving Gmail message to trash: {e}")
            import traceback
            print(traceback.format_exc())
            return False
