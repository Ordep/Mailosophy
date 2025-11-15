from flask_login import UserMixin
from app import db
from werkzeug.security import generate_password_hash, check_password_hash

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
    open_to_new_ideas = db.Column(db.Boolean, default=True)
    keep_inbox_on_manual = db.Column(db.Boolean, default=True)
    last_synced_at = db.Column(db.DateTime)
    
    # Admin flag
    is_admin = db.Column(db.Boolean, default=False)
    
    created_at = db.Column(db.DateTime, default=db.func.now())
    
    # Relationships
    emails = db.relationship('Email', backref='user', lazy=True, cascade='all, delete-orphan')
    labels = db.relationship('Label', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'
