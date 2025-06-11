from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from models import User

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('owner', 'Owner'), ('contractor', 'Contractor')], validators=[DataRequired()])
    submit = SubmitField('Register')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use a different email.')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken. Please choose a different one.')

class ProjectForm(FlaskForm):
    project_name = StringField('Project Name', validators=[DataRequired(), Length(min=3, max=120)])
    submit = SubmitField('Create Project')

class AdminProjectForm(FlaskForm):
    project_name = StringField('Project Name', validators=[DataRequired(), Length(min=3, max=120)])
    owner_id = SelectField('Project Owner', coerce=int, validators=[DataRequired()])
    contractor_id = SelectField('Project Contractor', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Create Project')
    
    def __init__(self, *args, **kwargs):
        super(AdminProjectForm, self).__init__(*args, **kwargs)
        # Populate owner and contractor choices
        owners = User.query.filter_by(role='owner').all()
        contractors = User.query.filter_by(role='contractor').all()
        
        self.owner_id.choices = [(0, '-- Select Owner --')] + [(owner.id, f"{owner.username} ({owner.email})") for owner in owners]
        self.contractor_id.choices = [(0, '-- Select Contractor --')] + [(contractor.id, f"{contractor.username} ({contractor.email})") for contractor in contractors]
        
    def validate_owner_id(self, field):
        if field.data == 0:
            raise ValidationError('Please select a project owner.')
            
    def validate_contractor_id(self, field):
        if field.data == 0:
            raise ValidationError('Please select a project contractor.')

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
    message = TextAreaField('Message', validators=[DataRequired()], render_kw={"placeholder": "Ask a question about the project documents..."})
    submit = SubmitField('Send')

class AdminUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    role = SelectField('Role', choices=[('owner', 'Owner'), ('contractor', 'Contractor')], validators=[DataRequired()])
    submit = SubmitField('Create User')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use a different email.')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken. Please choose a different one.')

class ChangePasswordForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')
