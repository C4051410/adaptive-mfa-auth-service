from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=30)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class TOTPForm(FlaskForm):
    # Form for entering the 6-digit TOTP code
    totp = StringField('TOTP Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')

class CAPTCHAForm(FlaskForm):
    # A placeholder for a simple text CAPTCHA
    # In a real-world app, you'd integrate Google reCAPTCHA or hCaptcha
    captcha_input = StringField('Enter the CAPTCHA text', validators=[DataRequired()])
    submit = SubmitField('Verify CAPTCHA')