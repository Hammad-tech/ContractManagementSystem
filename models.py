from datetime import datetime
from flask_login import UserMixin
from extensions import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False, default='contractor')  # 'admin', 'owner', 'contractor'
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    # Relationships for projects
    created_projects = db.relationship('Project', backref='creator', foreign_keys='Project.creator_id', lazy=True)
    owned_projects = db.relationship('Project', backref='owner', foreign_keys='Project.owner_id', lazy=True)
    contracted_projects = db.relationship('Project', backref='contractor', foreign_keys='Project.contractor_id', lazy=True)
    
    # Relationship for chat messages
    chat_messages = db.relationship('ChatMessage', backref='user', lazy=True, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<User {self.username} ({self.role})>'

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    # Role-based user assignments
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Admin who created the project
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)   # Project owner
    contractor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Contractor
    
    # Project status
    status = db.Column(db.String(20), nullable=False, default='active')  # 'active', 'completed', 'on_hold'
    
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
    
    def get_participants(self):
        """Return all users who have access to this project"""
        return [self.owner, self.contractor]
    
    def has_access(self, user):
        """Check if user has access to this project"""
        return user.role == 'admin' or user.id in [self.owner_id, self.contractor_id]

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    extracted_text = db.Column(db.Text, nullable=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.now)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Track who uploaded
    document_type = db.Column(db.String(50), nullable=False, default='contract')  # 'contract', 'record'
    
    # Relationships
    risks = db.relationship('Risk', backref='document', lazy=True, cascade="all, delete-orphan")
    uploader = db.relationship('User', backref='uploaded_documents', foreign_keys=[uploaded_by])
    
    def __repr__(self):
        return f'<Document {self.filename}>'

class ProjectRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    record_type = db.Column(db.String(50), nullable=False)  # e.g., schedule, log, invoice
    filename = db.Column(db.String(255), nullable=False)
    extracted_text = db.Column(db.Text, nullable=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.now)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Track who uploaded
    
    # Relationships
    uploader = db.relationship('User', backref='uploaded_records', foreign_keys=[uploaded_by])
    
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
    user_role = db.Column(db.String(20), nullable=False, default='contractor')  # Role perspective for this risk
    
    def __repr__(self):
        return f'<Risk {self.risk_category} - Score: {self.risk_score} ({self.user_role})>'

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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_user = db.Column(db.Boolean, nullable=False)  # True for user, False for AI
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    
    def __repr__(self):
        return f'<ChatMessage {"User" if self.is_user else "AI"}: {self.message[:50]}...>'

class Claim(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    claim_id = db.Column(db.String(20), nullable=False)  # e.g., "001", "002"
    claim_type = db.Column(db.String(100), nullable=False)  # e.g., "Time Extension Claim"
    date_notified = db.Column(db.DateTime, nullable=False)
    claimant = db.Column(db.String(200), nullable=False)  # e.g., "ABC Construction Ltd"
    description = db.Column(db.Text, nullable=False)
    reference_documents = db.Column(db.Text, nullable=True)  # JSON or comma-separated list
    status = db.Column(db.String(50), nullable=False, default='Pending')  # Pending, Approved, Rejected, Active, etc.
    amount_claimed = db.Column(db.Float, nullable=True)  # Amount in USD
    time_extension_requested = db.Column(db.Integer, nullable=True)  # Days
    remarks = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    project = db.relationship('Project', backref='claims')
    creator = db.relationship('User', backref='created_claims', foreign_keys=[created_by])
    
    def __repr__(self):
        return f'<Claim {self.claim_id}: {self.claim_type}>'
