from app import db
from datetime import datetime

class Email(db.Model):
    __tablename__ = 'emails'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    message_id = db.Column(db.String(255), unique=True, nullable=False)
    sender = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text)
    html_body = db.Column(db.Text)
    received_date = db.Column(db.DateTime)
    is_read = db.Column(db.Boolean, default=False)
    is_starred = db.Column(db.Boolean, default=False)
    ai_suggested_labels = db.Column(db.Text)
    ai_suggestion_applied = db.Column(db.Boolean, default=False)
    is_important = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    
    # Relationships
    labels = db.relationship('Label', secondary='email_labels', backref='emails')
    
    def __repr__(self):
        return f'<Email {self.subject}>'

class Label(db.Model):
    __tablename__ = 'labels'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(80), nullable=False)
    color = db.Column(db.String(7), default='#0084FF')
    gmail_label_id = db.Column(db.String(128), nullable=True, index=True)
    is_predefined = db.Column(db.Boolean, default=False)
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=db.func.now())
    
    __table_args__ = (db.UniqueConstraint('user_id', 'name', name='unique_user_label'),)
    
    def __repr__(self):
        return f'<Label {self.name}>'

# Association table for many-to-many relationship
email_labels = db.Table('email_labels',
    db.Column('email_id', db.Integer, db.ForeignKey('emails.id'), primary_key=True),
    db.Column('label_id', db.Integer, db.ForeignKey('labels.id'), primary_key=True)
)
