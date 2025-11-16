from flask_login import UserMixin
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
import json
from sqlalchemy import inspect, text

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200))
    imap_email = db.Column(db.String(120))
    imap_password = db.Column(db.String(200))
    imap_server = db.Column(db.String(120), default='imap.gmail.com')
    
    # Google OAuth fields
    google_id = db.Column(db.String(255), unique=True, nullable=True)
    google_access_token = db.Column(db.Text)
    google_refresh_token = db.Column(db.Text)
    google_token_expires_at = db.Column(db.DateTime)
    is_google_connected = db.Column(db.Boolean, default=False)
    auto_sync_minutes = db.Column(db.Integer, default=0)
    keep_inbox_on_manual = db.Column(db.Boolean, default=True)
    last_synced_at = db.Column(db.DateTime)
    active_custom_model_id = db.Column(db.Integer, db.ForeignKey('custom_models.id'))
    
    # Admin flag
    is_admin = db.Column(db.Boolean, default=False)
    
    created_at = db.Column(db.DateTime, default=db.func.now())
    
    # Relationships
    emails = db.relationship('Email', backref='user', lazy=True, cascade='all, delete-orphan')
    labels = db.relationship('Label', backref='user', lazy=True, cascade='all, delete-orphan')
    training_examples = db.relationship(
        'TrainingExample',
        backref='user',
        lazy=True,
        cascade='all, delete-orphan',
        foreign_keys='TrainingExample.user_id'
    )
    custom_models = db.relationship(
        'CustomModel',
        backref='user',
        lazy=True,
        cascade='all, delete-orphan',
        foreign_keys='CustomModel.user_id'
    )
    active_custom_model = db.relationship('CustomModel', foreign_keys=[active_custom_model_id], post_update=True, uselist=False)
    preferences = db.relationship('UserPreference', backref='user', uselist=False, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'


class UserPreference(db.Model):
    __tablename__ = 'user_preferences'

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    ai_summaries_enabled = db.Column(db.Boolean, default=True)
    sync_label_mode = db.Column(db.String(32), default='inbox')
    sync_label_ids = db.Column(db.Text, default='[]')
    auto_add_training_examples = db.Column(db.Boolean, default=False)
    email_delete_confirmation = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())

    def __repr__(self):
        return f'<UserPreference user_id={self.user_id}>'

    @property
    def sync_label_ids_list(self):
        if not self.sync_label_ids:
            return []
        try:
            parsed = json.loads(self.sync_label_ids)
            return [str(item) for item in parsed if item]
        except Exception:
            return []

    def set_sync_label_ids(self, ids):
        self.sync_label_ids = json.dumps(ids or [])

    @staticmethod
    def ensure_email_delete_column(engine):
        inspector = inspect(engine)
        columns = [col['name'] for col in inspector.get_columns('user_preferences')]
        if 'email_delete_confirmation' not in columns:
            with engine.connect() as conn:
                conn.execute(text('ALTER TABLE user_preferences ADD COLUMN email_delete_confirmation BOOLEAN DEFAULT 1'))
