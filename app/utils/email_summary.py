import json
import logging
import os
import re
import threading
from html import unescape
from typing import Optional

from flask import current_app

from app.utils.openai_helper import summarize_email_content

_CACHE_LOCK = threading.Lock()
_SUMMARY_CACHE: dict[str, str] = {}
_CACHE_LOADED = False
CACHE_FILENAME = 'email_summaries.json'
MAX_CACHE_ENTRIES = 2000


def _get_instance_dir() -> str:
    try:
        base = current_app.instance_path
    except RuntimeError:
        base = os.path.join(os.getcwd(), 'instance')
    os.makedirs(base, exist_ok=True)
    return base


def _get_cache_path() -> str:
    return os.path.join(_get_instance_dir(), CACHE_FILENAME)


def _load_cache_if_needed() -> None:
    global _CACHE_LOADED
    if _CACHE_LOADED:
        return
    path = _get_cache_path()
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as handle:
                data = json.load(handle)
                if isinstance(data, dict):
                    for key, value in data.items():
                        if isinstance(key, str) and isinstance(value, str):
                            _SUMMARY_CACHE[key] = value
        except Exception as exc:  # noqa: broad-except
            logging.warning('Failed to load email summary cache: %s', exc)
    _CACHE_LOADED = True


def _persist_cache() -> None:
    path = _get_cache_path()
    tmp_path = f"{path}.tmp"
    with open(tmp_path, 'w', encoding='utf-8') as handle:
        json.dump(_SUMMARY_CACHE, handle, ensure_ascii=False, indent=2)
    os.replace(tmp_path, path)


def _plain_text_from_email(email) -> str:
    if getattr(email, 'body', None) and email.body.strip():
        text = email.body
    elif getattr(email, 'html_body', None):
        text = re.sub(r'<[^>]+>', ' ', email.html_body)
    else:
        text = ''
    text = unescape(text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def get_ai_card_summary(email) -> Optional[str]:
    """Return cached AI summary for the email, generating it if missing."""
    message_id = getattr(email, 'message_id', None)
    if not message_id:
        return None

    with _CACHE_LOCK:
        _load_cache_if_needed()
        cached = _SUMMARY_CACHE.get(message_id)
        if cached:
            return cached

    plain_text = _plain_text_from_email(email)
    if not plain_text:
        return None

    summary = summarize_email_content(email.subject or '', plain_text, max_chars=190)
    if not summary:
        return None

    with _CACHE_LOCK:
        if len(_SUMMARY_CACHE) >= MAX_CACHE_ENTRIES:
            # Remove oldest inserted entries (iteration order preserved in Python 3.7+)
            remove_count = len(_SUMMARY_CACHE) - MAX_CACHE_ENTRIES + 1
            for _ in range(remove_count):
                _SUMMARY_CACHE.pop(next(iter(_SUMMARY_CACHE)))
        _SUMMARY_CACHE[message_id] = summary
        try:
            _persist_cache()
        except Exception as exc:  # noqa: broad-except
            logging.warning('Failed to persist email summary cache: %s', exc)

    return summary


def clear_summary_cache() -> None:
    """Utility hook for tests."""
    with _CACHE_LOCK:
        _SUMMARY_CACHE.clear()
        global _CACHE_LOADED
        _CACHE_LOADED = False
        cache_path = _get_cache_path()
        try:
            if os.path.exists(cache_path):
                os.remove(cache_path)
        except OSError:
            logging.debug('Unable to delete summary cache at %s', cache_path)
