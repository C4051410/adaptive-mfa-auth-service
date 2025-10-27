import os


class Config:
    # Flask General Config
    SECRET_KEY = os.environ.get(
        'SECRET_KEY') or 'A_very_strong_and_long_secret_key_for_production'  # Recommended: Use os.urandom(32)

    # Flask-SQLAlchemy
    SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Flask-WTF CSRF Token Timeout
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour

    # Flask-Limiter (Rate Limiting)
    RATELIMIT_DEFAULT_LIMIT = "7 per minute"
    RATELIMIT_STORAGE_URL = "memory://"  # Use in-memory storage for simplicity in this task

    # Security/Session Flags (Set via @app.after_request in __init__.py)
    # COOKIE_SECURE = True
    # COOKIE_HTTPONLY = True
    # COOKIE_SAMESITE = 'Lax'

    # Logging
    LOG_FILE = 'auth_events.log'

    # Testing/Debug flags
    DEBUG = True
    TESTING = True