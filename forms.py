from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class ProjectForm(FlaskForm):
    project_name = StringField('Project Name', validators=[DataRequired(), Length(min=3, max=120)])
    submit = SubmitField('Create Project')

class UploadDocumentForm(FlaskForm):
    document = FileField('Upload Contract', validators=[
        FileRequired(),
        FileAllowed(['pdf', 'docx', 'doc', 'txt'], 'Only PDF, DOCX, DOC, and TXT files are allowed!')
    ])
    submit = SubmitField('Upload Contract')

class UploadProjectRecordForm(FlaskForm):
    record = FileField('Upload Project Record', validators=[
        FileRequired(),
        FileAllowed(['pdf', 'docx', 'doc', 'txt'], 'Only PDF, DOCX, DOC, and TXT files are allowed!')
    ])
    record_type = SelectField('Record Type', choices=[
        ('schedule', 'Baseline Schedule'),
        ('log', 'Daily Site Report'),
        ('correspondence', 'Email/Correspondence'),
        ('change_order', 'Change Order'),
        ('invoice', 'Payment Record/Invoice'),
        ('other', 'Other')
    ])
    submit = SubmitField('Upload Record')

class ChatForm(FlaskForm):
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')
