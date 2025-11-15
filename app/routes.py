from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session, Response, stream_with_context, abort
from flask_login import login_user, logout_user, login_required, current_user
from app import db, login_manager
from app.models import User, Email, Label, email_labels
from app.utils.ai_labeler import AILabeler
from app.utils.google_oauth import GoogleOAuth, GmailHelper
from app.utils.gmail_sync import GmailSyncClient, GmailSyncError
from app.utils.openai_helper import suggest_labels_from_openai
from app.utils.config_service import (
    get_openai_configuration,
    set_config_values,
)
from app.utils.email_summary import get_ai_card_summary
from datetime import datetime
import os
import json
import re
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
AUTO_AI_ENABLED = os.getenv('ENABLE_AUTO_AI_SUGGESTIONS', '1').lower() not in ('0', 'false', 'off')
INBOX_LABEL_NAME = 'Inbox'
INBOX_LABEL_COLOR = os.getenv('INBOX_LABEL_COLOR', '#0ea5e9')
GMAIL_SYSTEM_LABELS = {
    'important',
    'work',
    'spam',
    'personal',
    'social',
    'promotions',
    'updates',
    'forums',
    'newsletter',
    'starred',
    'unread',
    'category_personal',
    'category_social',
    'category_promotions',
    'category_updates',
    'category_forums',
    INBOX_LABEL_NAME.lower(),
}
GMAIL_SYNC_MAX_MESSAGES_ENV = os.getenv('GMAIL_SYNC_MAX_MESSAGES')
DEFAULT_OPENAI_MODEL = os.getenv('OPENAI_MODEL', 'gpt-3.5-turbo')
try:
    GMAIL_SYNC_MAX_MESSAGES = int(GMAIL_SYNC_MAX_MESSAGES_ENV) if GMAIL_SYNC_MAX_MESSAGES_ENV else None
    if GMAIL_SYNC_MAX_MESSAGES is not None and GMAIL_SYNC_MAX_MESSAGES <= 0:
        GMAIL_SYNC_MAX_MESSAGES = None
except ValueError:
    GMAIL_SYNC_MAX_MESSAGES = None


def _mark_user_synced(user):
    """Persist the moment a user finishes a sync."""
    try:
        user.last_synced_at = datetime.utcnow()
        db.session.commit()
    except Exception:
        logger.exception("Failed to update last sync timestamp for user %s", getattr(user, 'id', 'unknown'))
        db.session.rollback()

def build_label_tree(labels):
    tree = {}

    def sort_key(name):
        lower = name.lower()
        if lower == INBOX_LABEL_NAME.lower():
            return (0, lower)
        return (1, lower)

    def dict_to_list(children):
        ordered = sorted(children.items(), key=lambda item: sort_key(item[0]))
        result = []
        for key, node in ordered:
            result.append({
                'name': node['name'],
                'label': node.get('label'),
                'children': dict_to_list(node['children'])
            })
        return result

    for label in sorted(labels, key=lambda l: l.name.lower()):
        if label.name.lower() in GMAIL_SYSTEM_LABELS:
            continue
        parts = [part.strip() for part in label.name.split('/') if part.strip()]
        if not parts:
            continue
        current = tree
        for idx, part in enumerate(parts):
            if part not in current:
                current[part] = {'name': part, 'children': {}, 'label': None}
            node = current[part]
            if idx == len(parts) - 1:
                node['label'] = label
            current = node['children']

    return dict_to_list(tree)


def build_label_contexts(labels):
    contexts = []
    for label in labels:
        if label.name.lower() in GMAIL_SYSTEM_LABELS:
            continue
        tokens = set(
            token.lower()
            for token in re.split(r'[/\s,_-]+', label.name)
            if len(token) > 2
        )
        if label.description:
            tokens.update(
                token.lower()
                for token in re.split(r'[/\s,_-]+', label.description)
                if len(token) > 2
            )
        contexts.append({
            'name': label.name,
            'description': label.description or '',
            'keywords': ', '.join(sorted(tokens))
        })
    return contexts


def sanitize_ai_suggestions(labels):
    """Remove disallowed/system labels from AI suggestions."""
    disallowed = {INBOX_LABEL_NAME.lower()}
    sanitized = []
    seen = set()
    for label in labels or []:
        if not isinstance(label, str):
            continue
        normalized = label.strip()
        if not normalized:
            continue
        lowered = normalized.lower()
        if lowered in disallowed or lowered in seen:
            continue
        seen.add(lowered)
        sanitized.append(normalized)
    return sanitized


def ensure_inbox_label(user, commit=False):
    """Ensure the system Inbox label exists for the user."""
    label = Label.query.filter_by(user_id=user.id, name=INBOX_LABEL_NAME).first()
    if label:
        return label

    label = Label(
        user_id=user.id,
        name=INBOX_LABEL_NAME,
        color=INBOX_LABEL_COLOR,
        is_predefined=True,
        description='System Inbox label'
    )
    db.session.add(label)
    if commit:
        db.session.commit()
    else:
        db.session.flush()
    return label

# Create blueprints
main_bp = Blueprint('main', __name__)
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
email_bp = Blueprint('email', __name__, url_prefix='/email')
label_bp = Blueprint('label', __name__, url_prefix='/label')

# Initialize AI labeler and Google OAuth
ai_labeler = AILabeler()
google_oauth = GoogleOAuth()

# Login manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Main Routes
@main_bp.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))

@main_bp.route('/dashboard')
@login_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    label_param = request.args.get('label')
    force_all = (label_param == 'all')
    selected_label = None
    if label_param and label_param != 'all':
        try:
            selected_label = int(label_param)
        except (TypeError, ValueError):
            selected_label = None

    labels = Label.query.filter_by(user_id=current_user.id).all()
    inbox_label = next((lbl for lbl in labels if lbl.name.lower() == INBOX_LABEL_NAME.lower()), None)
    if not inbox_label:
        inbox_label = ensure_inbox_label(current_user, commit=True)
        if inbox_label:
            labels.append(inbox_label)

    if not force_all and selected_label is None and inbox_label:
        selected_label = inbox_label.id

    query = Email.query.filter_by(user_id=current_user.id)
    if selected_label:
        query = query.filter(Email.labels.any(Label.id == selected_label))

    emails = query.order_by(Email.received_date.desc()).paginate(page=page, per_page=25)
    
    for email_obj in emails.items:
        email_obj.ai_preview_labels = []
        if email_obj.ai_suggested_labels and not email_obj.ai_suggestion_applied:
            try:
                parsed = json.loads(email_obj.ai_suggested_labels)
                if isinstance(parsed, list):
                    email_obj.ai_preview_labels = [
                        label.strip() for label in parsed
                        if isinstance(label, str) and label.strip()
                    ][:3]
            except json.JSONDecodeError:
                email_obj.ai_preview_labels = []

        try:
            summary = get_ai_card_summary(email_obj)
        except Exception:
            summary = None
            logger.exception('Failed to build AI summary for email %s', email_obj.id)
        email_obj.card_summary = summary

    tree_source = [
        lbl for lbl in labels
        if (not inbox_label or lbl.id != inbox_label.id)
        and lbl.name.lower() not in GMAIL_SYSTEM_LABELS
    ]
    label_tree = build_label_tree(tree_source)
    
    total_emails = Email.query.filter_by(user_id=current_user.id).count()
    inbox_count = Email.query.filter(
        Email.user_id == current_user.id,
        Email.labels.any(Label.name.ilike(INBOX_LABEL_NAME))
    ).count()

    auto_sync_minutes = current_user.auto_sync_minutes or 0
    last_refresh_dt = current_user.last_synced_at
    if last_refresh_dt:
        last_refresh_display = last_refresh_dt.strftime('%b %d, %Y %I:%M %p UTC')
    else:
        last_refresh_display = None

    if auto_sync_minutes:
        unit = "minute" if auto_sync_minutes == 1 else "minutes"
        auto_sync_text = f"Auto sync enabled · every {auto_sync_minutes} {unit}."
    else:
        auto_sync_text = "Auto sync disabled · enable it in Settings to keep Mailosophy fresh."
    
    return render_template(
        'dashboard.html',
        emails=emails,
        labels=labels,
        label_tree=label_tree,
        inbox_label=inbox_label,
        system_labels=[],
        total_emails=total_emails,
        inbox_count=inbox_count,
        force_all=force_all,
        selected_label=selected_label,
        auto_sync_minutes=auto_sync_minutes,
        auto_sync_text=auto_sync_text,
        last_refresh_display=last_refresh_display
    )

@main_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    success_message = None
    error_message = None

    if request.method == 'POST':
        try:
            updated_fields = []
            form_name = request.form.get('form_name') or 'preferences'

            if form_name == 'preferences':
                if 'auto_sync_minutes' in request.form:
                    raw_value = (request.form.get('auto_sync_minutes') or '').strip()
                    minutes = int(raw_value) if raw_value else 0
                    minutes = max(0, min(720, minutes))
                    current_user.auto_sync_minutes = minutes
                    updated_fields.append('Auto sync interval')

                if 'keep_inbox_on_manual' in request.form or form_name == 'preferences':
                    keep_flag = request.form.get('keep_inbox_on_manual') == 'on'
                    current_user.keep_inbox_on_manual = keep_flag
                    updated_fields.append('Inbox retention on manual label' if keep_flag else 'Auto-remove on manual label')
            else:
                error_message = 'Unknown settings section.'
                db.session.rollback()
                return render_template('settings.html', success=success_message, error=error_message)

            db.session.commit()
            if updated_fields:
                success_message = 'Updated: ' + ', '.join(updated_fields)
            else:
                success_message = 'Nothing to update.'
        except ValueError:
            db.session.rollback()
            error_message = 'Auto sync interval must be a number between 0 and 720 minutes.'
        except Exception as e:
            db.session.rollback()
            logger.exception('Failed to save settings for user %s', current_user.id)
            error_message = f'Error saving settings: {str(e)}'

    return render_template('settings.html', success=success_message, error=error_message)


@main_bp.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_console():
    if not current_user.is_admin:
        abort(403)

    success_message = None
    error_message = None
    openai_config = get_openai_configuration()

    if request.method == 'POST':
        try:
            api_key = (request.form.get('openai_api_key') or '').strip()
            model_name = (request.form.get('openai_model') or '').strip() or DEFAULT_OPENAI_MODEL
            if not api_key:
                if not openai_config.get('api_key'):
                    raise ValueError('OpenAI API key is required.')
                api_key = openai_config['api_key']
            set_config_values({
                'openai_api_key': api_key,
                'openai_model': model_name,
            })
            success_message = 'OpenAI configuration saved.'
        except ValueError as exc:
            error_message = str(exc)
        except Exception as exc:  # noqa: broad-except
            logger.exception('Failed to save admin settings: %s', exc)
            error_message = f'Unexpected error: {exc}'

    # Refresh configuration after potential updates
    openai_config = get_openai_configuration()

    missing_requirements = []
    if not openai_config['api_key']:
        missing_requirements.append('OpenAI API key must be set for AI features.')

    return render_template(
        'admin.html',
        success=success_message,
        error=error_message,
        openai_config=openai_config,
        missing_requirements=missing_requirements,
    )

# Auth Routes
@auth_bp.route('/login')
def login():
    return render_template('login.html')

@auth_bp.route('/google')
def google_login():
    """Redirect to Google OAuth login"""
    print("=== Google Login Route Called ===")
    print(f"GOOGLE_CLIENT_ID: {os.getenv('GOOGLE_CLIENT_ID')}")
    print(f"GOOGLE_CLIENT_SECRET: {'SET' if os.getenv('GOOGLE_CLIENT_SECRET') else 'NOT SET'}")
    print(f"GOOGLE_REDIRECT_URI: {os.getenv('GOOGLE_REDIRECT_URI')}")
    
    if os.getenv('GOOGLE_CLIENT_ID') and os.getenv('GOOGLE_CLIENT_SECRET'):
        try:
            authorization_url, state = google_oauth.get_authorization_url()
            print(f"Generated authorization URL: {authorization_url[:100]}...")
            print(f"Generated state: {state}")
            session['oauth_state'] = state
            print(f"State saved to session: {session.get('oauth_state')}")
            print(f"Redirecting to: {authorization_url}")
            return redirect(authorization_url)
        except Exception as e:
            import traceback
            print(f"Google OAuth Error: {e}")
            print(traceback.format_exc())
            return render_template('login.html', error=f"OAuth Error: {str(e)}"), 500
    else:
        error_msg = "Google OAuth is not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your .env file."
        print(error_msg)
        return render_template('login.html', error=error_msg), 400

@auth_bp.route('/google/callback')
def google_callback():
    """Handle Google OAuth callback"""
    try:
        print("=== Google OAuth Callback Started ===")
        
        # Verify state
        state = request.args.get('state')
        print(f"State from URL: {state}")
        print(f"State in session: {session.get('oauth_state')}")
        
        if state != session.get('oauth_state'):
            print("State mismatch!")
            return redirect(url_for('auth.login'))
        
        # Get authorization code
        code = request.args.get('code')
        print(f"Authorization code: {code[:20]}..." if code else "No code")
        
        if not code:
            print("No authorization code received")
            return redirect(url_for('auth.login'))
        
        # Exchange code for credentials
        print("Exchanging code for token...")
        credentials = google_oauth.exchange_code_for_token(code)
        print(f"Credentials: {credentials}")
        
        if not credentials:
            print("Failed to exchange code for credentials")
            return redirect(url_for('auth.login'))
        
        # Get user info
        print("Getting user info...")
        user_info = google_oauth.get_user_info(credentials)
        print(f"User info: {user_info}")
        
        if not user_info:
            print("Failed to get user info")
            return redirect(url_for('auth.login'))
        
        # Find or create user
        user = User.query.filter_by(google_id=user_info['id']).first()
        
        if not user:
            # Check if email exists
            user = User.query.filter_by(email=user_info['email']).first()
            
            if user:
                # Link Google to existing account
                print(f"Linking Google to existing user: {user.email}")
                user.google_id = user_info['id']
            else:
                # Create new user
                print(f"Creating new user: {user_info['email']}")
                user = User(
                    username=user_info['email'].split('@')[0],
                    email=user_info['email'],
                    google_id=user_info['id']
                )
                db.session.add(user)
        
        # Update Google credentials
        user.google_access_token = credentials.token
        user.google_refresh_token = credentials.refresh_token
        user.is_google_connected = True
        
        db.session.commit()
        print(f"User saved: {user.email}")
        
        # Create predefined labels if not exists
        if not Label.query.filter_by(user_id=user.id).first():
            print("Creating predefined labels...")
            predefined = ai_labeler.get_predefined_labels()
            for label_name, label_config in predefined.items():
                label = Label(
                    user_id=user.id,
                    name=label_name,
                    color=label_config['color'],
                    is_predefined=True,
                    description=f"Auto-labeled {label_name} emails"
                )
                db.session.add(label)
            db.session.commit()
        
        print(f"Logging in user: {user.email}")
        login_user(user)
        print("=== OAuth Callback Completed Successfully ===")
        return redirect(url_for('main.dashboard'))
    
    except Exception as e:
        import traceback
        error_msg = f"OAuth callback error: {str(e)}"
        print(error_msg)
        print(traceback.format_exc())
        return render_template('login.html', error=error_msg), 500

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

# Email Routes
@email_bp.route('/sync', methods=['GET', 'POST'])
@login_required
def sync_emails():
    """Sync emails via Gmail API with streaming updates."""
    logger.info("Starting sync request for user %s (google_connected=%s)", current_user.id, current_user.is_google_connected)

    def generate():
        import sys
        try:
            print("=== SYNC STARTED ===", file=sys.stderr, flush=True)
            if not (current_user.is_google_connected and current_user.google_access_token):
                logger.warning("User %s attempted sync without Google connection", current_user.id)
                yield f"data: {json.dumps({'error': 'Connect your Google Workspace account to sync emails.'})}\n\n"
                return
            yield from _sync_with_gmail(sys)
        except Exception as e:
            import traceback
            print("=== SYNC ERROR ===", file=sys.stderr, flush=True)
            print(traceback.format_exc(), file=sys.stderr, flush=True)
            logger.exception("Sync failed for user %s", current_user.id)
            yield f"data: {json.dumps({'error': f'Sync error: {str(e)}. Check server logs for details.'})}\n\n"

    def _sync_with_gmail(sys):
        logger.info("User %s syncing via Gmail API", current_user.id)
        label_sync_result = _sync_gmail_labels_for_user(current_user)
        if label_sync_result.get('success'):
            yield f"data: {json.dumps({'status': 'labels', 'message': label_sync_result.get('message')})}\n\n"
        else:
            logger.info(
                "User %s Gmail label sync skipped or failed: %s",
                current_user.id,
                label_sync_result.get('message')
            )
            yield f"data: {json.dumps({'status': 'labels', 'message': label_sync_result.get('message', 'Label sync skipped')})}\n\n"
        yield f"data: {json.dumps({'status': 'connecting', 'message': 'Connecting to Gmail API...'})}\n\n"
        client = _get_gmail_client()
        if not client:
            logger.warning("User %s Gmail client unavailable (likely missing/expired token)", current_user.id)
            yield f"data: {json.dumps({'error': 'Unable to connect to Gmail API. Please reconnect your Google account.'})}\n\n"
            return

        existing_count = Email.query.filter_by(user_id=current_user.id).count()
        max_fetch = GMAIL_SYNC_MAX_MESSAGES
        if max_fetch is not None:
            max_fetch = max(max_fetch, existing_count)

        try:
            message_ids = client.list_message_ids(max_total=max_fetch)
        except GmailSyncError as exc:
            logger.warning("User %s Gmail list failed: %s - attempting token refresh", current_user.id, exc)
            client = _refresh_gmail_client()
            if not client:
                logger.error("User %s Gmail token refresh failed: %s", current_user.id, exc)
                yield f"data: {json.dumps({'error': f'Gmail API error: {exc}'})}\n\n"
                return
            message_ids = client.list_message_ids(max_total=max_fetch)

        total = len(message_ids)
        yield f"data: {json.dumps({'status': 'fetching', 'message': f'Fetching {total} Gmail messages...', 'total': total, 'progress': 0})}\n\n"
        logger.info("User %s Gmail sync will fetch %s messages", current_user.id, total)
        fetched = []
        for idx, msg_id in enumerate(message_ids, start=1):
            try:
                fetched.append(client.fetch_message(msg_id))
            except GmailSyncError as exc:
                logger.error("User %s Gmail fetch failed for message %s: %s", current_user.id, msg_id, exc)
                yield f"data: {json.dumps({'error': f'Error fetching Gmail message: {exc}'})}\n\n"
                return

            if idx % 5 == 0 or idx == total:
                yield f"data: {json.dumps({'status': 'fetching', 'message': f'Fetching emails... ({idx}/{total})', 'total': total, 'progress': idx})}\n\n"

        yield from _persist_emails(fetched, 'gmail', sys)
        logger.info("User %s fetched %s Gmail messages", current_user.id, len(fetched))

    def _get_gmail_client():
        token = current_user.google_access_token
        if not token:
            return None
        return GmailSyncClient(token)

    def _refresh_gmail_client():
        if not current_user.google_refresh_token:
            return None
        new_token = google_oauth.refresh_access_token(current_user.google_refresh_token)
        if not new_token:
            return None
        logger.info("User %s Gmail token refreshed", current_user.id)
        current_user.google_access_token = new_token
        db.session.commit()
        return GmailSyncClient(new_token)

    def _persist_emails(all_emails, source, sys):
        existing_message_ids = set(
            e.message_id for e in Email.query.filter_by(user_id=current_user.id).with_entities(Email.message_id).all()
        )
        server_message_ids = set(e['message_id'] for e in all_emails)

        yield f"data: {json.dumps({'status': 'processing', 'message': f'Processing {len(all_emails)} emails...', 'total': len(all_emails)})}\n\n"
        logger.info("User %s processing %s emails (%s existing)", current_user.id, len(all_emails), len(existing_message_ids))

        synced_count = 0
        new_emails_to_insert = [e for e in all_emails if e['message_id'] not in existing_message_ids]
        new_email_payloads = []
        inbox_label = ensure_inbox_label(current_user)

        for idx, email_data in enumerate(new_emails_to_insert, 1):
            email_obj = Email(
                user_id=current_user.id,
                message_id=email_data.get('message_id'),
                sender=email_data['sender'],
                subject=email_data['subject'],
                body=email_data.get('body') or '',
                html_body=email_data.get('html_body') or '',
                received_date=email_data['received_date']
            )
            db.session.add(email_obj)
            synced_count += 1
            new_email_payloads.append({
                'message_id': email_data.get('message_id'),
                'subject': email_data.get('subject'),
                'body': email_data.get('body'),
                'html_body': email_data.get('html_body')
            })

            if inbox_label and inbox_label not in email_obj.labels:
                email_obj.labels.append(inbox_label)

            if synced_count % 50 == 0:
                db.session.commit()

            if idx % 25 == 0:
                yield f"data: {json.dumps({'status': 'syncing', 'progress': idx, 'total': len(new_emails_to_insert), 'synced': synced_count})}\n\n"

        deleted_count = 0
        yield f"data: {json.dumps({'status': 'cleaning', 'message': 'Checking for deleted emails...'})}\n\n"
        local_emails = Email.query.filter_by(user_id=current_user.id).all()
        total_local = len(local_emails)
        for idx, local_email in enumerate(local_emails, 1):
            if local_email.message_id not in server_message_ids:
                db.session.delete(local_email)
                deleted_count += 1
            if idx % 50 == 0 or idx == total_local:
                yield f"data: {json.dumps({'status': 'cleaning', 'message': f'Checking for deleted emails... ({idx}/{total_local})'})}\n\n"

        db.session.commit()

        if new_email_payloads:
            yield from _auto_generate_ai_labels(new_email_payloads, sys)

        _mark_user_synced(current_user)

        message = f'Completed! Synced {synced_count} new emails'
        if deleted_count > 0:
            message += f', deleted {deleted_count} emails'
        yield f"data: {json.dumps({'status': 'complete', 'synced': synced_count, 'deleted': deleted_count, 'message': message})}\n\n"
        logger.info("User %s sync completed via %s (synced=%s deleted=%s)", current_user.id, source, synced_count, deleted_count)
        print(f"=== SYNC COMPLETED via {source.upper()} ===", file=sys.stderr, flush=True)

    def _auto_generate_ai_labels(new_email_payloads, sys):
        if not AUTO_AI_ENABLED or not new_email_payloads:
            return
        openai_config = get_openai_configuration()
        if not (os.getenv('OPENAI_API_KEY') or openai_config.get('api_key')):
            logger.info("Skipping auto AI suggestions for user %s: OpenAI key not configured", current_user.id)
            return

        total = len(new_email_payloads)
        logger.info("User %s auto-generating AI suggestions for %s emails", current_user.id, total)
        yield f"data: {json.dumps({'status': 'ai', 'message': f'Generating AI suggestions for {total} new emails...'})}\n\n"

        label_contexts = build_label_contexts(Label.query.filter_by(user_id=current_user.id).all())
        updated = 0

        for idx, payload in enumerate(new_email_payloads, 1):
            subject = payload.get('subject') or ''
            combined_body = (payload.get('body') or '') + "\n" + (payload.get('html_body') or '')
            try:
                suggestions = suggest_labels_from_openai(subject, combined_body, label_contexts or None)
                suggestions = sanitize_ai_suggestions(suggestions)
            except Exception:
                logger.exception("Auto AI suggestion failed for user %s message %s", current_user.id, payload.get('message_id'))
                continue

            if not suggestions:
                continue

            email_obj = Email.query.filter_by(user_id=current_user.id, message_id=payload.get('message_id')).first()
            if not email_obj:
                continue

            email_obj.ai_suggested_labels = json.dumps(suggestions)
            email_obj.ai_suggestion_applied = False
            updated += 1

            if idx % 5 == 0 or idx == total:
                yield f"data: {json.dumps({'status': 'ai', 'message': f'AI tagging progress {idx}/{total}'})}\n\n"

        if updated:
            db.session.commit()
            yield f"data: {json.dumps({'status': 'ai', 'message': f'AI suggestions ready for {updated} emails'})}\n\n"
        else:
            yield f"data: {json.dumps({'status': 'ai', 'message': 'AI did not find suggestions for new emails'})}\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')

def _sync_gmail_labels_for_user(user):
    """Fetch Gmail labels and mirror them locally for the provided user."""
    if not user.is_google_connected:
        return {
            'success': False,
            'message': 'Google account not connected. Please reconnect your Google account.',
            'synced': 0,
            'skipped': 0,
            'deleted': 0
        }

    try:
        access_token = user.google_access_token
        gmail_labels = GmailHelper.get_gmail_labels(access_token) if access_token else None

        if gmail_labels is None and user.google_refresh_token:
            new_access_token = GoogleOAuth().refresh_access_token(user.google_refresh_token)
            if new_access_token:
                user.google_access_token = new_access_token
                db.session.commit()
                gmail_labels = GmailHelper.get_gmail_labels(new_access_token)

        if gmail_labels is None:
            return {
                'success': False,
                'message': 'Failed to fetch Gmail labels. Please try reconnecting your Google account.',
                'synced': 0,
                'skipped': 0,
                'deleted': 0
            }

        label_colors = ['#0084FF', '#28a745', '#dc3545', '#ffc107', '#17a2b8', '#6f42c1', '#fd7e14', '#20c997']
        color_index = 0
        gmail_label_names = set()
        synced_count = 0
        skipped_count = 0

        for gmail_label in gmail_labels:
            label_name = gmail_label['name']
            label_type = gmail_label['type']

            if label_type == 'system':
                skipped_count += 1
                continue

            gmail_label_names.add(label_name)

            existing_label = Label.query.filter_by(
                user_id=user.id,
                name=label_name
            ).first()

            if not existing_label:
                new_label = Label(
                    user_id=user.id,
                    name=label_name,
                    color=label_colors[color_index % len(label_colors)],
                    is_predefined=False,
                    description='Synced from Gmail'
                )
                db.session.add(new_label)
                synced_count += 1
                color_index += 1
            else:
                skipped_count += 1

        local_gmail_labels = Label.query.filter_by(
            user_id=user.id,
            is_predefined=False
        ).filter(Label.description.like('%Synced from Gmail%')).all()

        deleted_count = 0
        for local_label in local_gmail_labels:
            if local_label.name not in gmail_label_names:
                db.session.delete(local_label)
                deleted_count += 1

        db.session.commit()

        return {
            'success': True,
            'message': f'Synced {synced_count} Gmail labels ({skipped_count} system labels or duplicates skipped, {deleted_count} deleted)',
            'synced': synced_count,
            'skipped': skipped_count,
            'deleted': deleted_count
        }
    except Exception as exc:
        logger.exception('Error syncing Gmail labels for user %s', user.id)
        return {
            'success': False,
            'message': f'Error syncing Gmail labels: {exc}',
            'synced': 0,
            'skipped': 0,
            'deleted': 0
        }


@email_bp.route('/sync-gmail-labels', methods=['POST'])
@login_required
def sync_gmail_labels():
    """Retained endpoint to trigger Gmail label sync manually."""
    result = _sync_gmail_labels_for_user(current_user)
    status = 200 if result.get('success') else 400
    return jsonify(result), status

@email_bp.route('/<int:email_id>')
@login_required
def view_email(email_id):
    """View single email"""
    email_obj = Email.query.filter_by(id=email_id, user_id=current_user.id).first_or_404()
    email_obj.is_read = True
    db.session.commit()

    suggestions = []
    if email_obj.ai_suggested_labels:
        try:
            suggestions = json.loads(email_obj.ai_suggested_labels)
        except json.JSONDecodeError:
            suggestions = []

    saved_label_names = {label.name.strip().lower() for label in email_obj.labels}
    filtered_suggestions = []
    seen = set()
    for label in suggestions:
        if not isinstance(label, str):
            continue
        cleaned = label.strip()
        if not cleaned:
            continue
        lower = cleaned.lower()
        if lower in saved_label_names or lower in seen:
            continue
        filtered_suggestions.append(cleaned)
        seen.add(lower)

    labels = Label.query.filter_by(user_id=current_user.id).all()
    inbox_label = next((lbl for lbl in labels if lbl.name.lower() == INBOX_LABEL_NAME.lower()), None)
    if not inbox_label:
        inbox_label = ensure_inbox_label(current_user, commit=True)
        if inbox_label:
            labels.append(inbox_label)

    tree_source = [
        lbl for lbl in labels
        if (not inbox_label or lbl.id != inbox_label.id)
        and lbl.name.lower() not in GMAIL_SYSTEM_LABELS
    ]
    label_tree = build_label_tree(tree_source)
    applied_label_ids = {lbl.id for lbl in email_obj.labels}

    return render_template(
        'email_detail.html',
        email=email_obj,
        ai_suggestions=filtered_suggestions,
        label_tree=label_tree,
        applied_label_ids=applied_label_ids
    )

@email_bp.route('/<int:email_id>/label', methods=['POST'])
@login_required
def add_label_to_email(email_id):
    """Add label to email"""
    email_obj = Email.query.filter_by(id=email_id, user_id=current_user.id).first_or_404()
    data = request.get_json()
    
    label = Label.query.filter_by(
        id=data.get('label_id'),
        user_id=current_user.id
    ).first_or_404()
    
    gmail_synced = False
    if label not in email_obj.labels:
        email_obj.labels.append(label)
        db.session.commit()
        gmail_synced = _sync_labels_to_gmail(current_user, email_obj, [label.name])
    
    return jsonify({'success': True, 'gmail_synced': gmail_synced})

@email_bp.route('/<int:email_id>/label/<int:label_id>', methods=['DELETE'])
@login_required
def remove_label_from_email(email_id, label_id):
    """Remove label from email"""
    email_obj = Email.query.filter_by(id=email_id, user_id=current_user.id).first_or_404()
    label = Label.query.filter_by(id=label_id, user_id=current_user.id).first_or_404()
    
    if label in email_obj.labels:
        if len(email_obj.labels) <= 1:
            return jsonify({'success': False, 'message': 'Emails must have at least one label. Add another label before removing this one.'}), 400
        removed_label_name = label.name
        email_obj.labels.remove(label)
        db.session.commit()
        gmail_synced = _remove_labels_from_gmail(current_user, email_obj, [removed_label_name])
        return jsonify({'success': True, 'gmail_synced': gmail_synced})
    
    return jsonify({'success': False, 'message': 'Label not attached to email.'}), 404


@email_bp.route('/purge', methods=['POST'])
@login_required
def purge_all_emails():
    """Delete every stored email for the authenticated user."""
    try:
        email_ids = [
            row.id for row in Email.query.with_entities(Email.id).filter_by(user_id=current_user.id)
        ]
        if not email_ids:
            return jsonify({'success': True, 'message': 'No emails to delete for this account.'})

        assoc_result = db.session.execute(
            email_labels.delete().where(email_labels.c.email_id.in_(email_ids))
        )
        deleted_emails = Email.query.filter(Email.id.in_(email_ids)).delete(synchronize_session=False)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Deleted {deleted_emails} emails and {assoc_result.rowcount} label links.'
        })
    except Exception as exc:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error purging emails: {exc}'}), 500

# Label Routes
@label_bp.route('/create', methods=['POST'])
@login_required
def create_label():
    """Create new label"""
    data = request.get_json()
    
    # Check if label already exists
    existing = Label.query.filter_by(
        user_id=current_user.id,
        name=data.get('name')
    ).first()
    
    if existing:
        return jsonify({'success': False, 'message': 'Label already exists'})
    
    label = Label(
        user_id=current_user.id,
        name=data.get('name'),
        color=data.get('color', '#0084FF'),
        description=data.get('description')
    )
    
    db.session.add(label)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'label': {
            'id': label.id,
            'name': label.name,
            'color': label.color
        }
    })

@label_bp.route('/<int:label_id>', methods=['DELETE'])
@login_required
def delete_label(label_id):
    """Delete label"""
    label = Label.query.filter_by(id=label_id, user_id=current_user.id).first_or_404()
    
    # Don't allow deletion of predefined labels
    if label.is_predefined:
        return jsonify({'success': False, 'message': 'Cannot delete predefined labels'})
    
    db.session.delete(label)
    db.session.commit()
    
    return jsonify({'success': True})


@email_bp.route('/<int:email_id>/ai-suggest', methods=['POST'])
@login_required
def suggest_labels(email_id):
    """Generate AI label suggestions for an email using OpenAI."""
    email_obj = Email.query.filter_by(id=email_id, user_id=current_user.id).first_or_404()
    content = (email_obj.body or '') + "\n" + (email_obj.html_body or '')

    label_contexts = build_label_contexts(Label.query.filter_by(user_id=current_user.id).all())
    logger.info("User %s generating AI suggestions for email %s", current_user.id, email_id)
    try:
        suggestions = suggest_labels_from_openai(email_obj.subject, content, label_contexts or None)
        suggestions = sanitize_ai_suggestions(suggestions)
    except Exception as exc:
        logger.exception("AI suggestion failed for user %s email %s", current_user.id, email_id)
        return jsonify({'success': False, 'message': str(exc)}), 500

    if not suggestions:
        logger.info("AI suggestion returned no labels for user %s email %s", current_user.id, email_id)
        return jsonify({'success': False, 'message': 'No clear suggestions returned. Try again with more email content.'}), 400

    email_obj.ai_suggested_labels = json.dumps(suggestions)
    email_obj.ai_suggestion_applied = False
    db.session.commit()
    return jsonify({'success': True, 'suggestions': suggestions})


@email_bp.route('/<int:email_id>/ai-accept', methods=['POST'])
@login_required
def accept_ai_labels(email_id):
    """Apply AI suggested labels to the email and sync to Gmail if available."""
    email_obj = Email.query.filter_by(id=email_id, user_id=current_user.id).first_or_404()
    if not email_obj.ai_suggested_labels:
        return jsonify({'success': False, 'message': 'No AI suggestions to apply.'}), 400

    try:
        suggestions = json.loads(email_obj.ai_suggested_labels)
    except json.JSONDecodeError:
        suggestions = []

    if not suggestions:
        return jsonify({'success': False, 'message': 'No AI suggestions found.'}), 400

    payload = request.get_json(silent=True) or {}
    target_label = payload.get('label')
    labels_to_apply = suggestions
    if target_label:
        normalized = target_label.strip().lower()
        labels_to_apply = [
            label for label in suggestions
            if isinstance(label, str) and label.strip().lower() == normalized
        ]
        if not labels_to_apply:
            return jsonify({'success': False, 'message': f"Label '{target_label}' is not part of the AI suggestions."}), 404

    applied = []
    predefined = ai_labeler.get_predefined_labels()

    for label_name in labels_to_apply:
        if not label_name:
            continue
        label = Label.query.filter_by(user_id=current_user.id, name=label_name).first()
        if not label:
            color = predefined.get(label_name.lower(), {}).get('color', '#0084FF')
            label = Label(
                user_id=current_user.id,
                name=label_name,
                color=color,
                description='AI suggested label'
            )
            db.session.add(label)
            db.session.flush()

        if label not in email_obj.labels:
            email_obj.labels.append(label)
            applied.append(label.name)

    if applied:
        remaining = [
            label for label in suggestions
            if label not in applied
        ]
        if remaining:
            email_obj.ai_suggested_labels = json.dumps(remaining)
            email_obj.ai_suggestion_applied = False
        else:
            email_obj.ai_suggested_labels = None
            email_obj.ai_suggestion_applied = True
    else:
        email_obj.ai_suggestion_applied = True
    db.session.commit()

    inbox_label = ensure_inbox_label(current_user, commit=False)
    removed_inbox = False
    should_remove_inbox = not bool(current_user.keep_inbox_on_manual)
    if should_remove_inbox and inbox_label and inbox_label in email_obj.labels:
        email_obj.labels.remove(inbox_label)
        db.session.commit()
        removed_inbox = True

    gmail_synced = False
    if applied and current_user.is_google_connected and current_user.google_access_token:
        gmail_synced = _sync_labels_to_gmail(current_user, email_obj, applied)
        if removed_inbox:
            _remove_labels_from_gmail(current_user, email_obj, [inbox_label.name])
    logger.info("User %s applied AI labels %s to email %s (gmail_synced=%s)", current_user.id, applied, email_id, gmail_synced)

    return jsonify({
        'success': True,
        'applied': applied,
        'gmail_synced': gmail_synced,
        'removed_inbox': removed_inbox
    })


@email_bp.route('/<int:email_id>/ai-dismiss', methods=['POST'])
@login_required
def dismiss_ai_label(email_id):
    """Remove a pending AI suggestion from an email."""
    payload = request.get_json(silent=True) or {}
    label_to_remove = payload.get('label')

    if not label_to_remove:
        return jsonify({'success': False, 'message': 'No label specified.'}), 400

    email_obj = Email.query.filter_by(id=email_id, user_id=current_user.id).first_or_404()
    if not email_obj.ai_suggested_labels:
        return jsonify({'success': False, 'message': 'No AI suggestions to modify.'}), 400

    try:
        suggestions = json.loads(email_obj.ai_suggested_labels)
    except json.JSONDecodeError:
        suggestions = []

    if not isinstance(suggestions, list):
        suggestions = []

    normalized = str(label_to_remove).strip()
    filtered = [label for label in suggestions if str(label).strip() != normalized]

    if len(filtered) == len(suggestions):
        return jsonify({'success': False, 'message': 'Label not found in suggestions.'}), 404

    if filtered:
        email_obj.ai_suggested_labels = json.dumps(filtered)
        email_obj.ai_suggestion_applied = False
    else:
        email_obj.ai_suggested_labels = None
        email_obj.ai_suggestion_applied = False

    db.session.commit()
    logger.info("User %s dismissed AI label '%s' on email %s", current_user.id, label_to_remove, email_id)

    return jsonify({'success': True, 'remaining': filtered})


def _move_emails_to_label(email_ids, target_label_id, remove_inbox=False):
    if not email_ids:
        return jsonify({'success': False, 'message': 'No emails provided.'}), 400
    label = Label.query.filter_by(id=target_label_id, user_id=current_user.id).first()
    if not label:
        return jsonify({'success': False, 'message': 'Label not found.'}), 404

    inbox_label = ensure_inbox_label(current_user, commit=False)
    processed = []

    for email_id in email_ids:
        try:
            email_id = int(email_id)
        except (TypeError, ValueError):
            continue
        email_obj = Email.query.filter_by(id=email_id, user_id=current_user.id).first()
        if not email_obj:
            continue

        added = False
        removed = False
        if label not in email_obj.labels:
            email_obj.labels.append(label)
            added = True
        if remove_inbox and inbox_label and inbox_label in email_obj.labels and inbox_label.id != label.id:
            email_obj.labels.remove(inbox_label)
            removed = True
        processed.append((email_obj, added, removed))

    if not processed:
        return jsonify({'success': False, 'message': 'No matching emails found.'}), 404

    db.session.commit()

    if current_user.is_google_connected and current_user.google_access_token:
        for email_obj, added, removed in processed:
            if added:
                _sync_labels_to_gmail(current_user, email_obj, [label.name])
            if removed and inbox_label:
                _remove_labels_from_gmail(current_user, email_obj, [inbox_label.name])

    moved_ids = [email_obj.id for email_obj, _, _ in processed]
    removed_inbox_ids = [
        email_obj.id for email_obj, _, removed in processed if removed
    ]

    return jsonify({
        'success': True,
        'moved_ids': moved_ids,
        'removed_inbox_ids': removed_inbox_ids
    })


@email_bp.route('/<int:email_id>/move', methods=['POST'])
@login_required
def move_email(email_id):
    data = request.get_json(silent=True) or {}
    target_label_id = data.get('label_id')
    remove_inbox = bool(data.get('remove_inbox'))
    if not target_label_id:
        return jsonify({'success': False, 'message': 'Missing target label.'}), 400
    return _move_emails_to_label([email_id], target_label_id, remove_inbox=remove_inbox)


@email_bp.route('/move', methods=['POST'])
@login_required
def move_emails_bulk():
    data = request.get_json(silent=True) or {}
    target_label_id = data.get('label_id')
    email_ids = data.get('email_ids') or []
    remove_inbox = bool(data.get('remove_inbox'))
    if not target_label_id:
        return jsonify({'success': False, 'message': 'Missing target label.'}), 400
    if not email_ids:
        single_id = data.get('email_id')
        if single_id is None:
            return jsonify({'success': False, 'message': 'Missing email identifiers.'}), 400
        email_ids = [single_id]
    return _move_emails_to_label(email_ids, target_label_id, remove_inbox=remove_inbox)


@email_bp.route('/delete', methods=['POST'])
@login_required
def delete_emails():
    """Delete selected emails for the current user."""
    payload = request.get_json(silent=True) or {}
    ids = payload.get('email_ids') or payload.get('ids')

    if not ids:
        return jsonify({'success': False, 'message': 'No emails selected.'}), 400

    try:
        email_ids = list({int(eid) for eid in ids})
    except (TypeError, ValueError):
        return jsonify({'success': False, 'message': 'Invalid email identifiers provided.'}), 400

    if not email_ids:
        return jsonify({'success': False, 'message': 'No emails selected.'}), 400

    emails = Email.query.filter(
        Email.user_id == current_user.id,
        Email.id.in_(email_ids)
    ).all()

    if not emails:
        return jsonify({'success': False, 'message': 'No matching emails found.'}), 404

    deleted = len(emails)
    remote_failures = 0
    for email_obj in emails:
        if current_user.is_google_connected and email_obj.message_id:
            try:
                if not _trash_email_in_gmail(current_user, email_obj):
                    remote_failures += 1
            except Exception as exc:
                remote_failures += 1
                logger.exception("Failed to trash Gmail message for email %s: %s", email_obj.id, exc)
        if email_obj.labels:
            email_obj.labels.clear()
        db.session.delete(email_obj)

    db.session.commit()
    logger.info(
        "User %s deleted %s emails (remote failures: %s)",
        current_user.id,
        deleted,
        remote_failures
    )
    return jsonify({
        'success': True,
        'deleted': deleted,
        'remote_deleted': deleted - remote_failures,
        'remote_failed': remote_failures
    })


def _sync_labels_to_gmail(user, email_obj, label_names):
    """Apply accepted labels back to Gmail if possible."""
    access_token = user.google_access_token
    if not access_token:
        return False

    label_ids = []
    for name in label_names:
        label_id = GmailHelper.ensure_label(access_token, name)
        if not label_id and user.google_refresh_token:
            new_token = GoogleOAuth().refresh_access_token(user.google_refresh_token)
            if new_token:
                user.google_access_token = new_token
                db.session.commit()
                label_id = GmailHelper.ensure_label(new_token, name)
        if label_id:
            label_ids.append(label_id)

    if not label_ids:
        return False

    if GmailHelper.apply_labels_to_message(user.google_access_token, email_obj.message_id, label_ids):
        return True

    # Retry once with refreshed token if available
    if user.google_refresh_token:
        new_token = GoogleOAuth().refresh_access_token(user.google_refresh_token)
        if new_token:
            user.google_access_token = new_token
            db.session.commit()
            success = GmailHelper.apply_labels_to_message(new_token, email_obj.message_id, label_ids)
            if not success:
                logger.warning("User %s Gmail label apply failed even after token refresh", user.id)
            return success
    logger.warning("User %s Gmail label apply failed (no refresh token or apply error)", user.id)
    return False


def _remove_labels_from_gmail(user, email_obj, label_names):
    """Remove labels from Gmail message if possible."""
    if not label_names or not user.is_google_connected or not user.google_access_token:
        return False

    def resolve_label_ids(token):
        ids = []
        for name in label_names:
            if name.lower() == INBOX_LABEL_NAME.lower():
                ids.append('INBOX')
                continue
            label_id = GmailHelper.find_label_id(token, name)
            if label_id:
                ids.append(label_id)
        return ids

    access_token = user.google_access_token
    label_ids = resolve_label_ids(access_token)
    if not label_ids:
        return False

    if GmailHelper.remove_labels_from_message(access_token, email_obj.message_id, label_ids):
        return True

    if user.google_refresh_token:
        new_token = GoogleOAuth().refresh_access_token(user.google_refresh_token)
        if new_token:
            user.google_access_token = new_token
            db.session.commit()
            label_ids = resolve_label_ids(new_token)
            if label_ids and GmailHelper.remove_labels_from_message(new_token, email_obj.message_id, label_ids):
                return True
    return False


def _trash_email_in_gmail(user, email_obj):
    """Move the Gmail message backing this email to trash if possible."""
    if not user.is_google_connected or not user.google_access_token or not email_obj.message_id:
        return False

    def attempt(token):
        return GmailHelper.move_message_to_trash(token, email_obj.message_id)

    if attempt(user.google_access_token):
        return True

    if not user.google_refresh_token:
        logger.warning("User %s Gmail trash failed (no refresh token)", user.id)
        return False

    new_token = GoogleOAuth().refresh_access_token(user.google_refresh_token)
    if not new_token:
        logger.warning("User %s Gmail trash failed (refresh failed)", user.id)
        return False

    user.google_access_token = new_token
    db.session.commit()
    if attempt(new_token):
        return True

    logger.warning("User %s Gmail trash failed even after refresh", user.id)
    return False

@label_bp.route('/all')
@login_required
def get_labels():
    """Get all labels for current user"""
    labels = Label.query.filter_by(user_id=current_user.id).all()
    
    return jsonify({
        'success': True,
        'labels': [
            {
                'id': label.id,
                'name': label.name,
                'color': label.color,
                'is_predefined': label.is_predefined
            }
            for label in labels
        ]
    })


