import os
import sys

import click
from sqlalchemy import inspect, text

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import create_app, db


def ensure_users_column(engine):
    inspector = inspect(engine)
    columns = [col['name'] for col in inspector.get_columns('users')]
    if 'open_to_new_ideas' not in columns:
        click.echo('Adding users.open_to_new_ideas column...')
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE users ADD COLUMN open_to_new_ideas BOOLEAN DEFAULT 1"))
    else:
        click.echo('users.open_to_new_ideas already exists.')

    if 'last_synced_at' not in columns:
        click.echo('Adding users.last_synced_at column...')
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE users ADD COLUMN last_synced_at DATETIME"))
    else:
        click.echo('users.last_synced_at already exists.')


@click.command()
def upgrade_schema():
    """Ensure new tables/columns exist without requiring Alembic."""
    app = create_app()
    with app.app_context():
        engine = db.get_engine()
        ensure_users_column(engine)

        click.echo('Ensuring tables exist (including app_config)...')
        db.create_all()
        click.echo('Schema upgrade complete.')


if __name__ == '__main__':
    upgrade_schema()
