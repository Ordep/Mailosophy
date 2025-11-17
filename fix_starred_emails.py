"""
One-time migration script to fix existing starred emails.
This adds the Starred label to all emails that have is_important=True
but don't have the Starred label attached.

Run this with: python fix_starred_emails.py
"""

from app import create_app, db
from app.models import Email, Label, User

def fix_starred_emails():
    app = create_app()
    with app.app_context():
        # Get all users
        users = User.query.all()

        total_fixed = 0
        for user in users:
            print(f"\nProcessing user: {user.email or user.username}")

            # Ensure starred label exists for this user
            starred_label = Label.query.filter_by(
                user_id=user.id,
                name='Starred'
            ).first()

            if not starred_label:
                starred_label = Label(
                    user_id=user.id,
                    name='Starred',
                    color='#fbbf24',
                    is_predefined=True,
                    description='Starred emails',
                    gmail_label_id='STARRED'
                )
                db.session.add(starred_label)
                db.session.flush()
                print(f"  Created Starred label for user {user.id}")

            # Find all emails marked as important but missing the Starred label
            starred_emails = Email.query.filter_by(
                user_id=user.id,
                is_important=True
            ).all()

            fixed_count = 0
            for email in starred_emails:
                if starred_label not in email.labels:
                    email.labels.append(starred_label)
                    fixed_count += 1

            if fixed_count > 0:
                db.session.commit()
                print(f"  Fixed {fixed_count} starred email(s)")
                total_fixed += fixed_count
            else:
                print(f"  No emails need fixing")

        print(f"\nMigration complete! Fixed {total_fixed} total email(s)")

if __name__ == '__main__':
    fix_starred_emails()
