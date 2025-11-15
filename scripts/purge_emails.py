from app import create_app, db
from app.models.email import Email, email_labels

app = create_app()
with app.app_context():
    db.session.execute(email_labels.delete())
    deleted = Email.query.delete()
    db.session.commit()
    print(f"Deleted {deleted} emails")
