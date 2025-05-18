from datetime import datetime
from flask_login import UserMixin
from extensions import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    # Relationships
    projects = db.relationship('Project', backref='user', lazy=True, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<User {self.username}>'

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    # Relationships
    documents = db.relationship('Document', backref='project', lazy=True, cascade="all, delete-orphan")
    project_records = db.relationship('ProjectRecord', backref='project', lazy=True, cascade="all, delete-orphan")
    risks = db.relationship('Risk', backref='project', lazy=True, cascade="all, delete-orphan")
    entitlement_causation = db.relationship('EntitlementCausation', backref='project', lazy=True, cascade="all, delete-orphan")
    quantum = db.relationship('Quantum', backref='project', lazy=True, cascade="all, delete-orphan")
    counterclaims = db.relationship('Counterclaim', backref='project', lazy=True, cascade="all, delete-orphan")
    chat_messages = db.relationship('ChatMessage', backref='project', lazy=True, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<Project {self.project_name}>'

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    extracted_text = db.Column(db.Text, nullable=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.now)
    
    # Relationships
    risks = db.relationship('Risk', backref='document', lazy=True, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<Document {self.filename}>'

class ProjectRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    record_type = db.Column(db.String(50), nullable=False)  # e.g., schedule, log, invoice
    filename = db.Column(db.String(255), nullable=False)
    extracted_text = db.Column(db.Text, nullable=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.now)
    
    def __repr__(self):
        return f'<ProjectRecord {self.record_type}: {self.filename}>'

class Risk(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    clause_text = db.Column(db.Text, nullable=False)
    risk_category = db.Column(db.String(100), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    explanation = db.Column(db.Text, nullable=False)
    
    def __repr__(self):
        return f'<Risk {self.risk_category} - Score: {self.risk_score}>'

class EntitlementCausation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    category = db.Column(db.String(100))
    description = db.Column(db.Text)
    impact = db.Column(db.Text)
    findings = db.Column(db.Text)
    
    def __repr__(self):
        return f'<EntitlementCausation for Project {self.project_id}>'

class Quantum(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    cost_estimate = db.Column(db.Float)
    time_impact_days = db.Column(db.Integer)
    calculation_method = db.Column(db.Text)
    
    def __repr__(self):
        return f'<Quantum ${self.cost_estimate}, {self.time_impact_days} days>'

class Counterclaim(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    counterclaim_summary = db.Column(db.Text)
    
    def __repr__(self):
        return f'<Counterclaim for Project {self.project_id}>'

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    is_user = db.Column(db.Boolean, default=True)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    
    def __repr__(self):
        return f'<ChatMessage {"User" if self.is_user else "AI"} at {self.timestamp}>'
