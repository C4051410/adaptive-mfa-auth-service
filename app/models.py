import bcrypt
import os
from . import db
from flask_login import UserMixin


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    #Store bcrypt as hash rather than plaintext
    password_hash = db.Column(db.String(128), nullable=False)

    #multifactor auth
    totp_secret = db.Column(db.String(16), unique=True)  # 16-char base32 secret

    #Account lockout policy
    failed_login_attempts = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False)
    lockout_time = db.Column(db.DateTime)

    def set_password(self, password):
        #Hashs password using bcrypt
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        #Compare password to stored hash
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def generate_totp_secret(self):
        if not self.totp_secret:
            self.totp_secret = os.urandom(10).hex()  # Use hex for simple storage

    def __repr__(self):
        return f'<User {self.username}>'