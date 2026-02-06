from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, URL, Length
from flask_wtf.file import FileField, FileAllowed

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    role = SelectField('Role', choices=[('student', 'Student'), ('employer', 'Employer')])

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

class JobPostingForm(FlaskForm):
    title = StringField('Job Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    company = StringField('Company', validators=[DataRequired()])
    email = StringField('Contact Email', validators=[DataRequired(), Email()])
    apply_link = StringField('Apply Link', validators=[DataRequired(), URL()])
    location = StringField('Location', validators=[DataRequired()])
    job_type = SelectField('Type', choices=[('intern', 'Intern'), ('full-time', 'Full Time')])
    attachment = FileField('Attachment (PDF/DOC)', validators=[FileAllowed(['pdf', 'doc', 'docx'])])

class ReportForm(FlaskForm):
    reason = SelectField('Reason', choices=[
        ('fake_company', 'Fake Company'),
        ('phishing_link', 'Suspicious Link'),
        ('urgent_payment', 'Asks for Money'),
        ('other', 'Other')
    ])
    comment = TextAreaField('Details')