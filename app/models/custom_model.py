from app import db


class TrainingExample(db.Model):
    __tablename__ = 'training_examples'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    email_id = db.Column(db.Integer, db.ForeignKey('emails.id'), nullable=True)
    subject = db.Column(db.String(255))
    body = db.Column(db.Text)
    labels_json = db.Column(db.Text)
    source = db.Column(db.String(32), default='manual')
    created_at = db.Column(db.DateTime, default=db.func.now())


class CustomModel(db.Model):
    __tablename__ = 'custom_models'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(120))
    base_model = db.Column(db.String(80), default='gpt-3.5-turbo')
    openai_file_id = db.Column(db.String(100))
    openai_job_id = db.Column(db.String(100))
    openai_model_name = db.Column(db.String(120))
    status = db.Column(db.String(40), default='pending')
    training_example_count = db.Column(db.Integer, default=0)
    label_set = db.Column(db.Text)
    error_message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())
    completed_at = db.Column(db.DateTime)
