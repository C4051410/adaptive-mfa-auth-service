import os


class Config:
    #Flask initialisation
    SECRET_KEY = os.environ.get(
        'SECRET_KEY') or 'A_very_strong_and_long_secret_key_for_production'  # Recommended: Use os.urandom(32)


    SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Flask-WTF CSRF Token Timeout
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour

    #Rate limiter for flask
    RATELIMIT_DEFAULT_LIMIT = "7 per minute"
    RATELIMIT_STORAGE_URL = "memory://"  # Use in-memory storage for simplicity in this task

    LOG_FILE = 'auth_events.log'

    DEBUG = True
    TESTING = True