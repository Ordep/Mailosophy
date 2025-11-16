import base64
from datetime import datetime

import requests
from email.utils import parsedate_to_datetime


class GmailSyncError(Exception):
    pass


class GmailSyncClient:
    API_BASE = 'https://www.googleapis.com/gmail/v1/users/me'

    def __init__(self, access_token):
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        })

    def list_message_ids(self, max_total=None, label_ids=None, page_size=500):
        """Return a list of Gmail message IDs, paging through the inbox."""
        if page_size > 500:
            page_size = 500
        collected = []
        page_token = None
        if label_ids is None:
            label_ids = ['INBOX']

        while True:
            params = {
                'maxResults': page_size,
                'q': ''
            }
            if label_ids:
                params['labelIds'] = label_ids
            if page_token:
                params['pageToken'] = page_token

            resp = self.session.get(f'{self.API_BASE}/messages', params=params)
            if resp.status_code != 200:
                raise GmailSyncError(resp.text)

            data = resp.json() or {}
            collected.extend(item['id'] for item in data.get('messages', []))

            if max_total and len(collected) >= max_total:
                return collected[:max_total]

            page_token = data.get('nextPageToken')
            if not page_token:
                break

        return collected

    def fetch_message(self, message_id):
        resp = self.session.get(f'{self.API_BASE}/messages/{message_id}', params={'format': 'full'})
        if resp.status_code != 200:
            raise GmailSyncError(resp.text)
        return self._parse_gmail_message(resp.json())

    def _parse_gmail_message(self, payload):
        headers = {h['name'].lower(): h['value'] for h in payload.get('payload', {}).get('headers', [])}
        subject = headers.get('subject', '(No Subject)')
        sender = headers.get('from', 'Unknown')
        message_id = headers.get('message-id') or payload.get('id')

        date_header = headers.get('date')
        received_date = datetime.utcnow()
        if date_header:
            try:
                received_date = parsedate_to_datetime(date_header)
            except Exception:
                pass

        body_text, body_html = self._extract_bodies(payload.get('payload', {}))
        label_ids = payload.get('labelIds') or []
        if not body_html and body_text:
            body_html = '<br>'.join(body_text.splitlines())

        return {
            'sender': sender,
            'subject': subject,
            'body': body_text,
            'html_body': body_html,
            'received_date': received_date,
            'message_id': message_id,
            'label_ids': label_ids,
        }

    def _extract_bodies(self, part):
        mime_type = part.get('mimeType', '')
        data = part.get('body', {}).get('data')
        parts = part.get('parts', []) or []

        if mime_type == 'text/plain' and data:
            return self._decode_body(data), ''
        if mime_type == 'text/html' and data:
            return '', self._decode_body(data)

        text_body = ''
        html_body = ''
        for child in parts:
            text, html = self._extract_bodies(child)
            text_body += text
            html_body += html
        return text_body, html_body

    @staticmethod
    def _decode_body(encoded):
        if not encoded:
            return ''
        try:
            if isinstance(encoded, bytes):
                encoded_str = encoded.decode('utf-8', errors='ignore')
            else:
                encoded_str = encoded
            padding = '=' * (-len(encoded_str) % 4)
            decoded = base64.urlsafe_b64decode(encoded_str + padding)
            return decoded.decode('utf-8', errors='ignore')
        except Exception:
            return ''
