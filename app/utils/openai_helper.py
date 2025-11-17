import os
import json
import logging
import re
from typing import Optional
from openai import OpenAI


DEFAULT_OPENAI_MODEL = os.getenv('OPENAI_MODEL', 'gpt-3.5-turbo')
_client = None


def _get_openai_client() -> Optional[OpenAI]:
    """Get or create the OpenAI client singleton."""
    global _client
    if _client is None:
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            return None
        _client = OpenAI(api_key=api_key)
    return _client


def _resolve_openai_api_key() -> Optional[str]:
    return os.getenv('OPENAI_API_KEY')


def _resolve_openai_model() -> str:
    return os.getenv('OPENAI_MODEL') or DEFAULT_OPENAI_MODEL


def _ensure_openai_ready(raise_error: bool = True) -> Optional[str]:
    api_key = _resolve_openai_api_key()
    if not api_key:
        if raise_error:
            raise RuntimeError('OpenAI API key is not configured.')
        return None
    return _resolve_openai_model()


def _normalize_label_contexts(label_contexts):
    default_labels = [
        {'name': 'Work', 'description': 'Tasks, projects, or communication related to your job.', 'keywords': 'work, project, meeting, deadline'},
        {'name': 'Important', 'description': 'Time-sensitive or high-priority emails.', 'keywords': 'urgent, asap, important'},
        {'name': 'Personal', 'description': 'Friends, family, or personal matters.', 'keywords': 'family, friend, personal'},
        {'name': 'Newsletter', 'description': 'Recurring updates, marketing, or newsletters.', 'keywords': 'newsletter, subscription, digest'},
        {'name': 'Spam', 'description': 'Unwanted emails or scams.', 'keywords': 'spam, unsubscribe, offer'},
        {'name': 'Social', 'description': 'Notifications from social networks.', 'keywords': 'social, liked, comment'}
    ]

    if not label_contexts:
        return default_labels

    contexts = []
    for entry in label_contexts:
        if isinstance(entry, dict):
            contexts.append({
                'name': entry.get('name') or entry.get('label') or '',
                'description': entry.get('description', ''),
                'keywords': entry.get('keywords', '')
            })
        else:
            contexts.append({'name': str(entry), 'description': '', 'keywords': ''})

    return [ctx for ctx in contexts if ctx['name']]


def suggest_labels_from_openai(subject: str, body: str, label_contexts=None, model_override: Optional[str] = None):
    """Use OpenAI to suggest semantic labels for an email."""
    try:
        client = _get_openai_client()
        if not client:
            logging.error('OpenAI client is not configured - API key missing')
            raise RuntimeError('OpenAI client is not configured.')

        default_model = _ensure_openai_ready()
        model_name = model_override or default_model
        logging.info(f'Using OpenAI model: {model_name}')

        contexts = _normalize_label_contexts(label_contexts)

        label_descriptions = "\n".join(
            f"- {ctx['name']}: {ctx['description'] or 'No description provided.'} "
            f"Keywords: {ctx['keywords'] or 'N/A'}"
            for ctx in contexts
        )

        prompt = (
            "You are an assistant that classifies emails for a user. "
            "Only choose labels from the provided list and return their exact names as JSON.\n\n"
            f"Available labels:\n{label_descriptions}\n\n"
            "Instructions:\n"
            "- Return a JSON array with up to three label names.\n"
            "- Choose labels only if the email clearly matches the label meaning.\n"
            "- Do not invent new labels or alter the provided names.\n\n"
            f"Subject: {subject}\n"
            f"Body:\n{body[:6000]}\n\n"
            'Respond with JSON only, e.g. ["LabelA", "LabelB"].'
        )

        logging.info('Calling OpenAI API for label suggestions...')
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": "You classify emails into user-defined folders."},
                {"role": "user", "content": prompt},
            ],
            max_completion_tokens=120,
        )

        content = response.choices[0].message.content
        if content:
            content = content.strip()
        logging.info(f'OpenAI raw response: "{content}" (type: {type(content).__name__}, length: {len(content) if content else 0})')

        if not content:
            logging.error('OpenAI returned empty content')
            return []

        if content.startswith('```'):
            content = content.split('\n', 1)[1] if '\n' in content else content[3:]
            if content.endswith('```'):
                content = content.rsplit('\n', 1)[0] if '\n' in content[:-3] else content[:-3]
            content = content.strip()
            logging.info(f'Stripped markdown fences, new content: "{content}"')

        try:
            suggestions = json.loads(content)
            if isinstance(suggestions, list):
                result = [str(label).strip() for label in suggestions if str(label).strip()]
                logging.info(f'Parsed suggestions: {result}')
                return result
        except json.JSONDecodeError as e:
            logging.error(f'Failed to parse OpenAI response as JSON: {e}')
            pass

        logging.warning('No valid suggestions extracted from OpenAI response')
        return []
    except Exception as e:
        logging.error(f'Error in suggest_labels_from_openai: {e}', exc_info=True)
        raise


def _prepare_plain_text(subject: str, body: str) -> str:
    subject = (subject or '').strip()
    body = (body or '').strip()
    body = re.sub(r'<[^>]+>', ' ', body)
    body = re.sub(r'\s+', ' ', body)
    combined = f"{subject}. {body}".strip()
    return combined[:4000]


def summarize_email_content(subject: str, body: str, max_chars: int = 200) -> Optional[str]:
    """Return a short AI-generated summary suitable for card previews."""
    try:
        client = _get_openai_client()
        if not client:
            logging.warning('OpenAI client not configured; cannot summarize email.')
            return None

        model_name = _ensure_openai_ready(raise_error=False)
        if not model_name:
            logging.warning('OpenAI API key missing; cannot summarize email.')
            return None

        plain_text = _prepare_plain_text(subject, body)
        if not plain_text:
            logging.warning('No text content to summarize')
            return None

        max_chars = max(60, min(max_chars, 240))
        prompt = (
            "You are a concise email summarizer for a productivity dashboard.\n"
            "Summarize the following email in one sentence using no more than "
            f"{max_chars} characters. Use clear, action-focused language, avoid bullet points, "
            "quotes, or line breaks. Mention the key intent or action item.\n\n"
            f"Email content:\n{plain_text}\n\n"
            "Summary:"
        )

        logging.info('Calling OpenAI API for email summary...')
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": "You write polished, concise summaries."},
                {"role": "user", "content": prompt},
            ],
            max_completion_tokens=120,
        )

        raw = response.choices[0].message.content.strip()
        if len(raw) > max_chars:
            raw = raw[:max_chars - 1].rstrip() + '...'

        logging.info(f'Generated summary: {raw[:50]}...')
        return raw or None
    except Exception as exc:
        logging.error("OpenAI summarization failed: %s", exc, exc_info=True)
        return None


def ensure_openai_ready(raise_error: bool = True) -> Optional[str]:
    """Expose the credential/model resolution helper for other modules."""
    return _ensure_openai_ready(raise_error=raise_error)
