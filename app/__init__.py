import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import Config

# Initialize Extensions
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=["7 per minute"])


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions with the app
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Configure Flask-Login
    login_manager.login_view = 'main.login'
    login_manager.login_message_category = 'info'

    # Register Blueprints
    from .routes import main
    app.register_blueprint(main)

    # User loader for Flask-Login
    from .models import User  # Import here to avoid circular dependencies
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # --- Secure Session Management ---
    @app.before_request
    def before_request_hook():
        # Regenerate session ID *after* login is handled in routes.py
        # For non-logged in users, this helps defend against session fixation before login.
        if current_user.is_authenticated and 'session_regenerated' not in session:
            # We handle this post-login inside the route itself for the final token regeneration
            pass

    @app.after_request
    def set_secure_headers(response):
        # Implement secure cookie flags (Part A)
        if 'session' in session:
            session.permanent = False  # Default session to non-permanent
            # Set secure cookie flags
            response.headers['Set-Cookie'] = f'session={session.sid}; HttpOnly; Secure; SameSite=Lax; Path=/'

        # Content Security Policy (Optional, but good practice)
        response.headers[
            'Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'"

        return response

    # --- Logging Setup (Part D) ---
    if not app.debug:
        file_handler = RotatingFileHandler(app.config['LOG_FILE'], maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)

    return app