from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AlertForm(FlaskForm):
    customer = SelectField('Customer', coerce=int, validators=[DataRequired()])
    vuln_name = StringField('Vulnerability Name', validators=[DataRequired()])
    link = StringField('Reference Link')
    description = TextAreaField('Short Description', validators=[DataRequired()])
    submit = SubmitField('Add Alert')
