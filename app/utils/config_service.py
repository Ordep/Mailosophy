from __future__ import annotations

from typing import Dict, Optional

from app import db
from app.models import AppConfig


def get_config_value(key: str, default: Optional[str] = None) -> Optional[str]:
    if not key:
        return default
    record = AppConfig.query.filter_by(key=key).first()
    return record.value if record else default


def get_config_values(keys) -> Dict[str, Optional[str]]:
    if not keys:
        return {}
    records = AppConfig.query.filter(AppConfig.key.in_(list(keys))).all()
    mapping = {record.key: record.value for record in records}
    return {key: mapping.get(key) for key in keys}


def set_config_values(values: Dict[str, Optional[str]]) -> None:
    if not values:
        return
    keys = list(values.keys())
    existing = {
        cfg.key: cfg
        for cfg in AppConfig.query.filter(AppConfig.key.in_(keys)).all()
    }
    for key, value in values.items():
        record = existing.get(key)
        if value is None or value == '':
            if record:
                db.session.delete(record)
        else:
            if record:
                record.value = value
            else:
                db.session.add(AppConfig(key=key, value=value))
    db.session.commit()


def get_openai_configuration() -> Dict[str, Optional[str]]:
    data = get_config_values(['openai_api_key', 'openai_model'])
    return {
        'api_key': (data.get('openai_api_key') or '').strip() or None,
        'model': (data.get('openai_model') or '').strip() or None,
    }
