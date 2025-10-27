import pyotp
import qrcode
import io
import base64
import random
from datetime import datetime, timedelta
from flask import (
    Blueprint, render_template, redirect, url_for, request, flash,
    session, current_app, make_response
)
from flask_login import login_user, logout_user, current_user, login_required
from sqlalchemy import exc
from . import db, limiter  # Import limiter here
from .models import User
from .forms import LoginForm, TOTPForm, CAPTCHAForm

# Dictionary to store per-username failed login counts and CAPTCHA status (Part C)
# In a production app, this would use Redis/database for persistence across workers
login_attempts_info = {}

main = Blueprint('main', __name__)


# --- Helper Functions for Adaptive Security and Logging ---

def log_event(level, message, username=None):
    """Log an authentication event with IP address and timestamp."""
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    timestamp = datetime.utcnow().strftime('%Y/%m/%d %H:%M:%S UTC')

    log_message = f"[{timestamp}] IP:{ip_address} User:{username if username else 'N/A'} - {message}"

    if level == 'INFO':
        current_app.logger.info(log_message)
    elif level == 'WARNING':
        current_app.logger.warning(log_message)


def get_captcha_text():
    """Generates a simple random CAPTCHA string."""
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(random.choice(chars) for _ in range(6))


def check_adaptive_security(user):
    """
    Checks if a user is locked out or needs a CAPTCHA.
    Returns: ('locked', message) or ('captcha', message) or ('ok', None)
    """
    info = login_attempts_info.get(user.username, {'failures': 0, 'captcha_shown': False, 'lockout_end': None})

    # 1. Check Account Lockout (Part C)
    if user.is_locked and user.lockout_time and user.lockout_time > datetime.utcnow():
        time_left = user.lockout_time - datetime.utcnow()
        message = f"Account locked. Try again in {int(time_left.total_seconds() // 60)} minutes and {int(time_left.total_seconds() % 60)} seconds."
        log_event('WARNING', f"Account lock checked, still locked.", username=user.username)
        return 'locked', message
    elif user.is_locked and user.lockout_time and user.lockout_time <= datetime.utcnow():
        # Lockout expired, reset status
        user.is_locked = False
        user.failed_login_attempts = 0
        user.lockout_time = None
        info['failures'] = 0
        db.session.commit()

    # 2. Check CAPTCHA Enforcement (Part C)
    if user.failed_login_attempts >= 3 and not info.get('captcha_solved'):
        log_event('INFO', f"CAPTCHA triggered due to {user.failed_login_attempts} failed attempts.",
                  username=user.username)
        # Store the correct CAPTCHA text in the session
        if 'captcha_text' not in session:
            session['captcha_text'] = get_captcha_text()
        return 'captcha', "Please solve the CAPTCHA before proceeding."

    return 'ok', None


# --- Routes ---

@main.route('/', methods=['GET', 'POST'])
@main.route('/login', methods=['GET', 'POST'])
@limiter.limit("7 per minute")  # Part C: Rate Limiting
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    captcha_form = CAPTCHAForm()

    # Handle CAPTCHA and Lockout status
    captcha_status = False
    lockout_status = False

    # Check if we need to show the CAPTCHA or if the user is locked
    if 'temp_username' in session:
        user = User.query.filter_by(username=session['temp_username']).first()
        if user:
            status, message = check_adaptive_security(user)
            if status == 'locked':
                flash(message, 'error')
                lockout_status = True
            elif status == 'captcha':
                flash(message, 'warning')
                captcha_status = True
                captcha_form.captcha_text = session['captcha_text']  # Pass text to template

    if request.method == 'POST':
        # CAPTCHA check
        if captcha_status and captcha_form.validate_on_submit():
            if captcha_form.captcha_input.data.upper() != session.get('captcha_text', '').upper():
                flash("Incorrect CAPTCHA.", 'error')
                log_event('WARNING', "Incorrect CAPTCHA attempt.", username=session.get('temp_username'))
                return render_template('login.html', form=form, captcha_form=captcha_form, captcha_status=True,
                                       captcha_text=session.get('captcha_text'))
            else:
                # CAPTCHA solved, allow standard login attempt now
                flash("CAPTCHA verified. Please enter your credentials.", 'success')
                login_attempts_info[session['temp_username']]['captcha_solved'] = True
                return redirect(url_for('main.login'))  # Redirect to clear CAPTCHA POST data

        # Standard Login attempt
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            user = User.query.filter_by(username=username).first()

            # Use temporary session for username check before password check to maintain adaptive security state
            session['temp_username'] = username

            # Check Lockout/Adaptive Security Status before processing credentials
            if user:
                status, message = check_adaptive_security(user)
                if status == 'locked':
                    flash(message, 'error')
                    return render_template('login.html', form=form, captcha_form=captcha_form, lockout_status=True)

                if user.check_password(password):
                    # --- SUCCESSFUL LOGIN ---
                    # 1. Reset security counters
                    user.failed_login_attempts = 0
                    login_attempts_info.pop(username, None)
                    db.session.commit()

                    # 2. Check for MFA setup
                    if user.totp_secret:
                        # Redirect to TOTP verification step
                        session['pre_auth_user_id'] = user.id
                        session.pop('temp_username', None)
                        flash('Password correct. Please enter your TOTP code.', 'info')
                        return redirect(url_for('main.verify_mfa'))
                    else:
                        # MFA not set up. Login and redirect to setup page.
                        # Part A: Regenerate session tokens after login
                        session.regenerate()
                        login_user(user)
                        log_event('INFO', "Successful login (MFA not setup). Session regenerated.",
                                  username=user.username)
                        flash('Login successful! Please set up Multi-Factor Authentication.', 'warning')
                        return redirect(url_for('main.setup_mfa'))

            # --- FAILED LOGIN ---
            log_event('WARNING', "Failed login attempt.", username=username)
            flash('Invalid username or password.', 'error')

            if user:
                # Update failed attempts for the specific user
                user.failed_login_attempts += 1
                db.session.commit()

                # Check for Lockout condition (Part C)
                if user.failed_login_attempts >= 5:
                    user.is_locked = True
                    user.lockout_time = datetime.utcnow() + timedelta(minutes=5)
                    db.session.commit()
                    log_event('WARNING', "Account locked for 5 minutes (5 failures).", username=user.username)
                    flash('Account locked for 5 minutes due to excessive failed attempts.', 'error')
                    return redirect(url_for('main.login'))

                # Check for CAPTCHA trigger (Part C)
                if user.failed_login_attempts >= 3:
                    session['captcha_text'] = get_captcha_text()  # Generate new CAPTCHA
                    login_attempts_info[username] = {'failures': user.failed_login_attempts, 'captcha_solved': False}
                    flash("Multiple failures. Please solve the CAPTCHA to proceed.", 'warning')
                    return redirect(url_for('main.login'))  # Redirect to re-render with CAPTCHA

    # Re-render the form for GET or failed POST
    return render_template('login.html', form=form, captcha_form=captcha_form, captcha_status=captcha_status,
                           captcha_text=session.get('captcha_text'))


@main.route('/verify-mfa', methods=['GET', 'POST'])
def verify_mfa():
    # Only proceed if the user has successfully passed password check
    user_id = session.get('pre_auth_user_id')
    if not user_id:
        flash('Authentication required.', 'error')
        return redirect(url_for('main.login'))

    user = User.query.get(user_id)
    if not user or not user.totp_secret:
        flash('MFA setup is incomplete or user not found.', 'error')
        session.pop('pre_auth_user_id', None)
        return redirect(url_for('main.login'))

    form = TOTPForm()

    if form.validate_on_submit():
        totp_code = form.totp.data

        # Verify TOTP code
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(totp_code):
            # --- MFA SUCCESS ---
            session.pop('pre_auth_user_id', None)

            # Part A: Regenerate session tokens after login
            session.regenerate()
            login_user(user)
            log_event('INFO', "Successful MFA verification and login. Session regenerated.", username=user.username)
            flash('MFA verification successful. Welcome!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            # --- MFA FAILURE ---
            log_event('WARNING', "Invalid TOTP code.", username=user.username)
            flash('Invalid TOTP code.', 'error')

    return render_template('verify_mfa.html', form=form)


@main.route('/setup-mfa', methods=['GET', 'POST'])
@login_required  # Must be logged in (even without MFA) to set it up
def setup_mfa():
    if current_user.totp_secret:
        flash('MFA is already set up.', 'info')
        return redirect(url_for('main.dashboard'))

    # Generate a secret and URL for the user
    if not current_user.totp_secret:
        current_user.generate_totp_secret()
        try:
            db.session.commit()
        except exc.SQLAlchemyError:
            db.session.rollback()
            flash("Error saving TOTP secret.", 'error')
            return redirect(url_for('main.dashboard'))

    # Generate the provisioning URI (the text the authenticator app uses)
    app_name = "CSC2031_Auth"
    uri = pyotp.totp.TOTP(current_user.totp_secret).provisioning_uri(
        current_user.username,
        issuer_name=app_name
    )

    # Generate QR Code (Part B)
    qr_img = qrcode.make(uri)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    qr_data_url = 'data:image/png;base64,' + base64.b64encode(buf.getvalue()).decode('utf-8')

    # After initial setup, redirect to verification route
    # For simplicity, we assume the user scans and verifies immediately
    return render_template(
        'setup_mfa.html',
        secret=current_user.totp_secret,
        qr_data_url=qr_data_url,
        uri=uri
    )


@main.route('/dashboard')
@login_required  # Part A: Protect sensitive routes
def dashboard():
    # If MFA is not set up, prompt user
    if not current_user.totp_secret:
        flash("Action required: Please set up Multi-Factor Authentication!", 'warning')

    return render_template('dashboard.html', username=current_user.username)


@main.route('/logout')
@login_required  # Ensures only logged-in users can log out
def logout():
    username = current_user.username
    logout_user()
    session.clear()  # Part A: Ensure session is fully cleared
    log_event('INFO', "Logout event.", username=username)
    flash('You have been logged out securely.', 'info')
    return redirect(url_for('main.login'))