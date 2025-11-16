"""
Google OAuth utility for Mailosophy
Handles Google authentication and token management
"""
import logging
import os
import re
import requests
from google.auth.transport.requests import Request
from google.oauth2 import id_token
from urllib.parse import urlencode

ENABLE_GMAIL_MODIFY_SCOPE = os.getenv('ENABLE_GMAIL_MODIFY_SCOPE', '0').lower() not in ('0', 'false', 'off')

logger = logging.getLogger(__name__)

class GoogleOAuth:
    def __init__(self):
        self.client_id = os.getenv('GOOGLE_CLIENT_ID')
        self.client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
        self.redirect_uri = os.getenv('GOOGLE_REDIRECT_URI', 'http://localhost:5000/auth/google/callback')
        self.auth_uri = 'https://accounts.google.com/o/oauth2/v2/auth'
        self.token_uri = 'https://oauth2.googleapis.com/token'
        scopes = [
            'https://www.googleapis.com/auth/gmail.labels',
            'https://www.googleapis.com/auth/gmail.modify',
        ]
        self.scopes = scopes
    
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
            logger.debug("Token exchange status=%s", response.status_code)
            
            if response.status_code == 200:
                tokens = response.json()
                # Create a credentials-like object
                class Credentials:
                    def __init__(self, token_data):
                        self.token = token_data.get('access_token')
                        self.refresh_token = token_data.get('refresh_token')
                        self.id_token = token_data.get('id_token')
                
                return Credentials(tokens)
            logger.warning("Token exchange failed (status=%s)", response.status_code)
            return None
                
        except Exception:
            logger.exception("Exception while exchanging OAuth code for token")
            return None
    
    def get_user_info(self, credentials):
        """Parse the ID token to extract user info without requesting additional profile scopes."""
        if not credentials or not credentials.id_token:
            return None
        if not self.client_id:
            logger.warning("Google OAuth client ID is not configured; cannot verify ID token.")
            return None
        try:
            info = id_token.verify_oauth2_token(
                credentials.id_token,
                Request(),
                self.client_id
            )
        except ValueError as exc:
            logger.warning("Invalid Google ID token: %s", exc)
            return None
        except Exception:
            logger.exception("Unexpected error verifying Google ID token")
            return None

        email = info.get('email')
        sub = info.get('sub')
        name = info.get('name') or (email.split('@')[0] if email else None)
        picture = info.get('picture')
        return {
            'id': sub,
            'email': email,
            'name': name,
            'picture': picture
        }
    
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
                return response.json().get('access_token')
            logger.warning("Refreshing Google access token failed (status=%s)", response.status_code)
            return None
        except Exception:
            logger.exception("Error refreshing Google access token")
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
        except Exception:
            logger.exception("Error building Gmail service")
            return None

    @staticmethod
    def get_gmail_labels(access_token):
        """Fetch all Gmail labels using Gmail API"""
        try:
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
                logger.warning("Fetching Gmail labels failed (status=%s)", response.status_code)
                return None

        except Exception:
            logger.exception("Error fetching Gmail labels")
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
                logger.warning("Creating Gmail label failed (status=%s)", response.status_code)
                return None
        except Exception:
            logger.exception("Error ensuring Gmail label")
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
                logger.warning("Searching Gmail message failed (status=%s)", search_resp.status_code)
                return False
            messages = search_resp.json().get('messages', [])
            if not messages:
                logger.warning("No Gmail message matched the RFC822 Message-ID")
                return False

            gmail_message_id = messages[0]['id']
            modify_resp = requests.post(
                f'{GmailHelper.API_BASE}/messages/{gmail_message_id}/modify',
                headers=headers,
                json={'addLabelIds': label_ids}
            )
            if modify_resp.status_code == 200:
                return True
            logger.warning("Applying Gmail labels failed (status=%s) for message %s", modify_resp.status_code, gmail_message_id)
            return False
        except Exception:
            logger.exception("Error applying Gmail labels")
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
                logger.warning("Searching Gmail message for removal failed (status=%s)", search_resp.status_code)
                return False
            messages = search_resp.json().get('messages', [])
            if not messages:
                logger.warning("No Gmail message matched the RFC822 Message-ID for removal")
                return False

            gmail_message_id = messages[0]['id']
            modify_resp = requests.post(
                f'{GmailHelper.API_BASE}/messages/{gmail_message_id}/modify',
                headers=headers,
                json={'removeLabelIds': label_ids}
            )
            if modify_resp.status_code == 200:
                return True
            logger.warning("Removing Gmail labels failed (status=%s) for message %s", modify_resp.status_code, gmail_message_id)
            return False
        except Exception:
            logger.exception("Error removing Gmail labels")
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
                logger.warning("Error searching Gmail message for trash (status=%s)", search_resp.status_code)

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
                logger.warning("Error trashing Gmail message %s (status=%s)", gmail_message_id, trash_resp.status_code)

            return False
        except Exception:
            logger.exception("Error moving Gmail message to trash")
            return False
