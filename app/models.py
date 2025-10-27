import bcrypt
import os
from . import db
from flask_login import UserMixin


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    # Store bcrypt hash instead of plaintext
    password_hash = db.Column(db.String(128), nullable=False)

    # Part B: Multi-Factor Authentication
    totp_secret = db.Column(db.String(16), unique=True)  # 16-char base32 secret

    # Part C: Account Lockout Policy
    failed_login_attempts = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False)
    lockout_time = db.Column(db.DateTime)

    def set_password(self, password):
        # Hash the password using bcrypt
        # bcrypt.gensalt() generates a salt, which is then included in the hash
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        # Check password against the stored hash
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def generate_totp_secret(self):
        # Generate a base32 secret for TOTP
        if not self.totp_secret:
            # os.urandom(10) generates 10 random bytes, then base32 encode it
            # This is equivalent to pyotp.random_base32()
            self.totp_secret = os.urandom(10).hex()  # Use hex for simple storage

    def __repr__(self):
        return f'<User {self.username}>'