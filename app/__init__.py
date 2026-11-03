import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

db = SQLAlchemy()


def create_app(config_override=None):
    """
    Application factory for PhishDetect AI Flask web application.
    """
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    app = Flask(
        __name__,
        instance_relative_config=True,
        template_folder=os.path.join(project_root, 'templates'),
        static_folder=os.path.join(project_root, 'static')
    )

    # Ensure instance folder exists for SQLite storage
    os.makedirs(app.instance_path, exist_ok=True)
    db_path = os.path.join(app.instance_path, 'phishdetect.db')

    app.config.from_mapping(
        SECRET_KEY=os.getenv('SECRET_KEY', 'phishdetect-dev-secret-key-2024'),
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{db_path}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
    )

    if config_override:
        app.config.update(config_override)

    db.init_app(app)

    with app.app_context():
        # Import models so SQLAlchemy metadata is aware of all tables
        from app import models  # noqa: F401
        db.create_all()

        # Initialize default settings
        from app.database import init_db
        init_db(app)

    # Register application blueprints
    from app.routes import main
    app.register_blueprint(main)

    return app


