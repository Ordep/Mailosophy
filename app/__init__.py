from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from sqlalchemy import inspect
from sqlalchemy import text
import logging
from logging.handlers import RotatingFileHandler
import os
from dotenv import load_dotenv

load_dotenv()

db = SQLAlchemy()
login_manager = LoginManager()


def create_app():
    app = Flask(__name__)

    # Configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///Mailosophy.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    # Ensure models are imported so db.create_all sees them
    from app import models  # noqa: F401

    # Create tables
    with app.app_context():
        db.create_all()
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        if 'user_preferences' in inspector.get_table_names():
            existing = {col['name'] for col in inspector.get_columns('user_preferences')}
            with db.engine.connect() as conn:
                if 'auto_add_training_examples' not in existing:
                    conn.execute(text('ALTER TABLE user_preferences ADD COLUMN auto_add_training_examples BOOLEAN DEFAULT 0'))
                if 'email_delete_confirmation' not in existing:
                    conn.execute(text('ALTER TABLE user_preferences ADD COLUMN email_delete_confirmation BOOLEAN DEFAULT 1'))
        from app.models.user import UserPreference
        UserPreference.ensure_email_delete_column(db.engine)

    # Register blueprints
    from app.routes import main_bp, auth_bp, email_bp, label_bp, start_auto_sync_worker
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(email_bp)
    app.register_blueprint(label_bp)

    # Ensure logging output is emitted even if the user didn't configure logging.
    log_path = os.path.join(os.getcwd(), 'logs')
    os.makedirs(log_path, exist_ok=True)
    logging.basicConfig(level=logging.DEBUG)
    root_logger = logging.getLogger()
    if not root_logger.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s')
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)
    file_handler = RotatingFileHandler(os.path.join(log_path, 'mailosophy.log'), maxBytes=10 * 1024 * 1024, backupCount=5)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s')
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)
    app.logger.setLevel(logging.DEBUG)

    # Kick off background auto-sync scheduler (idempotent).
    start_auto_sync_worker(app)

    # Ensure application logger is verbose
    app.logger.setLevel(logging.DEBUG)

    return app
