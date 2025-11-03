import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import Config

#Initialised extensions, used AI to use correct extensions
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=["7 per minute"])


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    #Initialised extensions for app, used AI to use correct extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    #Set up flask login
    login_manager.login_view = 'main.login'
    login_manager.login_message_category = 'info'

    #initialise blueprints
    from .routes import main
    app.register_blueprint(main)

    #Loader for user for flask login
    from .models import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))


    @app.before_request
    def before_request_hook():
        #Regenerate sessionid, from routes.py
        if current_user.is_authenticated and 'session_regenerated' not in session:
            pass

    @app.after_request
    def set_secure_headers(response):
        if 'session' in session:
            session.permanent = False
            #initialise cookie flags
            response.headers['Set-Cookie'] = f'session={session.sid}; HttpOnly; Secure; SameSite=Lax; Path=/'

        response.headers[
            'Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'"

        return response

    if not app.debug:
        file_handler = RotatingFileHandler(app.config['LOG_FILE'], maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)

    return app