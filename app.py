import os
import logging
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, session, abort, send_file, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy.exc import SQLAlchemyError
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape, A1, A3
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import json
from dotenv import load_dotenv
import tempfile
from functools import wraps
import concurrent.futures

# Load environment variables from .env file
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('SESSION_SECRET', 'default-secret-key')  # Fallback to default if not set

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PROJECT_RECORDS_FOLDER'] = 'project_records'
app.config['REPORTS_FOLDER'] = 'reports'  # Add reports folder

# Import extensions
from extensions import db, login_manager

# Initialize extensions
db.init_app(app)
login_manager.init_app(app)

# Create upload directories if they don't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROJECT_RECORDS_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)  # Create reports directory

# Import models and services
from models import User, Project, Document, ProjectRecord, Risk, EntitlementCausation, Quantum, Counterclaim, ChatMessage, Claim
from forms import LoginForm, RegistrationForm, ProjectForm, UploadDocumentForm, UploadProjectRecordForm, ChatForm, AdminProjectForm, AdminUserForm
from utils import extract_text_from_file, allowed_file
from openai_service import (analyze_contract_risks, analyze_project_records, 
                           assess_quantum, evaluate_counterclaims, 
                           suggest_dispute_strategy, chat_with_documents,
                           chunk_text, generate_claims)

# Role-based decorators
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def project_access_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        project_id = kwargs.get('project_id')
        if not project_id:
            abort(404)
            
        project = Project.query.get_or_404(project_id)
        
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
            
        # Check if user has access to this project
        if not project.has_access(current_user):
            flash('You do not have access to this project.', 'danger')
            return redirect(url_for('dashboard'))
            
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Create database tables within application context
with app.app_context():
    db.create_all()
    
    # Auto-seed users on first run
    def create_seed_users():
        """Create seed users if no users exist in the database"""
        try:
            # Check if any users exist
            user_count = User.query.count()
            
            if user_count == 0:
                app.logger.info("No users found. Creating seed users...")
                
                # User data to seed
                users_data = [
                    {
                        "username": "admin_user",
                        "email": "admin@example.com",
                        "password": "admin123",
                        "role": "admin"
                    },
                    {
                        "username": "owner_user",
                        "email": "owner@example.com",
                        "password": "owner123",
                        "role": "owner"
                    },
                    {
                        "username": "contractor_user",
                        "email": "contractor@example.com",
                        "password": "contractor123",
                        "role": "contractor"
                    }
                ]
                
                for user_data in users_data:
                    # Check if user already exists by email (double-check)
                    existing_user = User.query.filter_by(email=user_data["email"]).first()
                    
                    if not existing_user:
                        hashed_password = generate_password_hash(user_data["password"])
                        new_user = User(
                            username=user_data["username"],
                            email=user_data["email"],
                            password_hash=hashed_password,
                            role=user_data["role"]
                        )
                        db.session.add(new_user)
                        app.logger.info(f"Created {user_data['role']} user: {user_data['username']} ({user_data['email']})")
                
                db.session.commit()
                app.logger.info("✅ Seed users created successfully!")
                app.logger.info("Default login credentials:")
                for user in users_data:
                    app.logger.info(f"  - {user['role'].title()}: {user['email']} / {user['password']}")
                    
            else:
                app.logger.info(f"Database already has {user_count} users. Skipping seed creation.")
                
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creating seed users: {str(e)}")
    
    # Run the seed function
    create_seed_users()

# Authentication routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        login_type = request.form.get('login_type', 'user')
        user = User.query.filter_by(email=form.email.data).first()
        
        if user and check_password_hash(user.password_hash, form.password.data):
            # Validate role-based access
            if login_type == 'admin' and user.role != 'admin':
                flash('You do not have admin privileges. Please use the User Login tab.', 'danger')
                return render_template('login.html', form=form)
            elif login_type == 'user' and user.role == 'admin':
                flash('Admin users must use the Admin Login tab.', 'warning')
                return render_template('login.html', form=form)
            
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # Redirect users to login page instead
    flash('Account creation is now managed by administrators. Please contact your admin to create an account.', 'info')
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Admin routes
@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_dashboard():
    project_form = AdminProjectForm()
    user_form = AdminUserForm()
    
    # Handle project creation
    if project_form.validate_on_submit() and 'create_project' in request.form:
        new_project = Project(
            project_name=project_form.project_name.data,
            creator_id=current_user.id,
            owner_id=project_form.owner_id.data,
            contractor_id=project_form.contractor_id.data,
            status='active'
        )
        
        try:
            db.session.add(new_project)
            db.session.commit()
            flash('Project created successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Database error: {str(e)}")
            flash('An error occurred. Please try again.', 'danger')
    
    # Handle user creation
    if user_form.validate_on_submit() and 'create_user' in request.form:
        hashed_password = generate_password_hash(user_form.password.data)
        new_user = User(
            username=user_form.username.data,
            email=user_form.email.data,
            password_hash=hashed_password,
            role=user_form.role.data
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('User created successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Database error: {str(e)}")
            flash('An error occurred while creating user.', 'danger')
    
    # Get all projects created by this admin
    projects = Project.query.filter_by(creator_id=current_user.id).all()
    
    # Get all users for management
    users = User.query.filter(User.role != 'admin').all()
    
    return render_template('admin_dashboard.html', projects=projects, project_form=project_form, user_form=user_form, users=users)

@app.route('/admin/users')
@login_required
@admin_required
def manage_users():
    users = User.query.filter(User.role != 'admin').all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/project/<int:project_id>')
@login_required
@admin_required
def admin_project_overview(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the current admin created this project
    if project.creator_id != current_user.id:
        flash('You can only view projects you created.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    # Get project statistics
    documents = Document.query.filter_by(project_id=project_id).all()
    records = ProjectRecord.query.filter_by(project_id=project_id).all()
    risks = Risk.query.filter_by(project_id=project_id).all()
    
    return render_template('admin/project_overview.html', 
                         project=project, 
                         documents=documents, 
                         records=records, 
                         risks=risks)

@app.route('/admin/project/<int:project_id>/records')
@login_required
@admin_required
def admin_view_project_records(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the current admin created this project
    if project.creator_id != current_user.id:
        flash('You can only view projects you created.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    records = ProjectRecord.query.filter_by(project_id=project_id).all()
    return render_template('admin/project_records.html', project=project, records=records)

@app.route('/admin/project/<int:project_id>/documents')
@login_required
@admin_required
def admin_view_project_documents(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the current admin created this project
    if project.creator_id != current_user.id:
        flash('You can only view projects you created.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    documents = Document.query.filter_by(project_id=project_id).all()
    return render_template('admin/project_documents.html', project=project, documents=documents)

# Project management routes
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    # Role-based dashboard logic
    if current_user.role == 'admin':
        # Admin sees different dashboard - redirect to admin dashboard
        return redirect(url_for('admin_dashboard'))
    
    form = ProjectForm()
    
    # Regular users (owner/contractor) cannot create projects
    # Only view projects they're assigned to
    
    # Get projects based on user role
    if current_user.role == 'owner':
        projects = Project.query.filter_by(owner_id=current_user.id).all()
    elif current_user.role == 'contractor':
        projects = Project.query.filter_by(contractor_id=current_user.id).all()
    else:
        projects = []
    
    return render_template('dashboard.html', projects=projects, form=form)

@app.route('/project/<int:project_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the current admin created this project
    if project.creator_id != current_user.id:
        flash('You can only delete projects you created.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    try:
        # Delete related records first (due to foreign key constraints)
        Document.query.filter_by(project_id=project_id).delete()
        ProjectRecord.query.filter_by(project_id=project_id).delete()
        Risk.query.filter_by(project_id=project_id).delete()
        EntitlementCausation.query.filter_by(project_id=project_id).delete()
        Quantum.query.filter_by(project_id=project_id).delete()
        Counterclaim.query.filter_by(project_id=project_id).delete()
        ChatMessage.query.filter_by(project_id=project_id).delete()
        
        # Delete project
        db.session.delete(project)
        db.session.commit()
        flash('Project deleted successfully', 'success')
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Database error: {str(e)}")
        flash('An error occurred while deleting the project', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/project/<int:project_id>/change-status', methods=['POST'])
@login_required
@admin_required
def change_project_status(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the current admin created this project
    if project.creator_id != current_user.id:
        flash('You can only modify projects you created.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    new_status = request.form.get('status')
    valid_statuses = ['active', 'completed', 'on_hold']
    
    if new_status not in valid_statuses:
        flash('Invalid status selected.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    try:
        project.status = new_status
        db.session.commit()
        flash(f'Project status changed to {new_status.replace("_", " ").title()}', 'success')
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Database error: {str(e)}")
        flash('An error occurred while updating the project status', 'danger')
    
    return redirect(url_for('admin_dashboard'))

# Document management routes
@app.route('/project/<int:project_id>/upload', methods=['GET', 'POST'])
@login_required
@project_access_required
def upload_document(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Only owners and contractors can upload documents, not admins
    if current_user.role == 'admin':
        flash('Admins cannot upload documents. Only project owners and contractors can upload.', 'warning')
        return redirect(url_for('admin_dashboard'))
    
    contract_form = UploadDocumentForm()
    record_form = UploadProjectRecordForm()
    
    if contract_form.validate_on_submit() and contract_form.document.data:
        # Handle contract upload
        file = contract_form.document.data
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            try:
                # Extract text from document
                extracted_text = extract_text_from_file(file_path)
                
                # Save document in database
                new_document = Document(
                    project_id=project_id,
                    filename=filename,
                    extracted_text=extracted_text,
                    uploaded_at=datetime.now(),
                    uploaded_by=current_user.id,
                    document_type='contract'
                )
                
                db.session.add(new_document)
                db.session.commit()
                
                # Analyze contract for risks from owner and contractor perspectives only
                chunked_text = chunk_text(extracted_text)
                roles_to_analyze = ['owner', 'contractor']  # Admin will see both perspectives
                
                for role in roles_to_analyze:
                    for chunk in chunked_text:
                        risks = analyze_contract_risks(chunk, role)
                        
                        for risk in risks:
                            new_risk = Risk(
                                document_id=new_document.id,
                                project_id=project_id,
                                clause_text=risk['clause_text'],
                                risk_category=risk['risk_category'],
                                risk_score=risk['risk_score'],
                                explanation=risk['explanation'],
                                user_role=role  # Store risk for each role perspective
                            )
                            db.session.add(new_risk)
                
                db.session.commit()
                flash('Contract uploaded and analyzed successfully!', 'success')
                return redirect(url_for('view_document', project_id=project_id, document_id=new_document.id))
            
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error processing document: {str(e)}")
                flash('Error processing document', 'danger')
    
    elif record_form.validate_on_submit() and record_form.record.data:
        # Handle project record upload
        file = record_form.record.data
        record_type = record_form.record_type.data
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['PROJECT_RECORDS_FOLDER'], filename)
            file.save(file_path)
            
            try:
                # Extract text from record
                extracted_text = extract_text_from_file(file_path)
                
                # Save project record in database
                new_record = ProjectRecord(
                    project_id=project_id,
                    record_type=record_type,
                    filename=filename,
                    extracted_text=extracted_text,
                    uploaded_at=datetime.now(),
                    uploaded_by=current_user.id
                )
                
                db.session.add(new_record)
                db.session.commit()
                flash('Project record uploaded successfully!', 'success')
                return redirect(url_for('view_project_records', project_id=project_id))
            
            except Exception as e:
                app.logger.error(f"Error processing project record: {str(e)}")
                flash('Error processing project record', 'danger')
    
    return render_template('upload.html', project=project, contract_form=contract_form, record_form=record_form)

@app.route('/project/<int:project_id>/documents')
@login_required
@project_access_required
def view_project_documents(project_id):
    project = Project.query.get_or_404(project_id)
    # All project participants can see all documents uploaded to the project
    documents = Document.query.filter_by(project_id=project_id).all()
    return render_template('view_project_documents.html', project=project, documents=documents)

@app.route('/project/<int:project_id>/document/<int:document_id>')
@login_required
@project_access_required
def view_document(project_id, document_id):
    project = Project.query.get_or_404(project_id)
    document = Document.query.get_or_404(document_id)
    
    # Ensure document belongs to this project
    if document.project_id != project_id:
        abort(403)
    
    risks = Risk.query.filter_by(document_id=document_id).all()
    return render_template('view_document.html', project=project, document=document, risks=risks)

@app.route('/project/<int:project_id>/document/<int:document_id>/download')
@login_required
@project_access_required
def download_document(project_id, document_id):
    project = Project.query.get_or_404(project_id)
    document = Document.query.get_or_404(document_id)
    
    # Ensure document belongs to this project
    if document.project_id != project_id:
        abort(403)
    
    # Build file path
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], document.filename)
    
    # Check if file exists
    if not os.path.exists(file_path):
        flash('Document file not found', 'danger')
        return redirect(url_for('view_document', project_id=project_id, document_id=document_id))
    
    # Return the file
    return send_file(
        file_path,
        as_attachment=True,
        download_name=document.filename
    )

@app.route('/project/<int:project_id>/records')
@login_required
@project_access_required
def view_project_records(project_id):
    project = Project.query.get_or_404(project_id)
    records = ProjectRecord.query.filter_by(project_id=project_id).all()
    return render_template('view_project_records.html', project=project, records=records)

@app.route('/project/<int:project_id>/record/<int:record_id>/download')
@login_required
@project_access_required
def download_record(project_id, record_id):
    project = Project.query.get_or_404(project_id)
    record = ProjectRecord.query.get_or_404(record_id)
    
    # Ensure record belongs to this project
    if record.project_id != project_id:
        abort(403)
    
    # Build file path
    file_path = os.path.join(app.config['PROJECT_RECORDS_FOLDER'], record.filename)
    
    # Check if file exists
    if not os.path.exists(file_path):
        flash('Record file not found', 'danger')
        return redirect(url_for('view_project_records', project_id=project_id))
    
    # Return the file
    return send_file(
        file_path,
        as_attachment=True,
        download_name=record.filename
    )

@app.route('/project/<int:project_id>/risks')
@login_required
@project_access_required
def view_risks(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Role-specific risk filtering
    if current_user.role == 'admin':
        # Admin sees both owner and contractor risks
        risks = Risk.query.filter_by(project_id=project_id).all()
    else:
        # Users only see risks from their perspective
        risks = Risk.query.filter_by(project_id=project_id, user_role=current_user.role).all()
    
    return render_template('view_risks.html', project=project, risks=risks)

@app.route('/project/<int:project_id>/analyze-records', methods=['POST'])
@login_required
@project_access_required
def analyze_records(project_id):
    project = Project.query.get_or_404(project_id)
    
    try:
        # Get all project records and documents
        records = ProjectRecord.query.filter_by(project_id=project_id).all()
        documents = Document.query.filter_by(project_id=project_id).all()
        
        if not records and not documents:
            flash('No project records or documents found for analysis. Please upload some files first.', 'warning')
            return redirect(url_for('view_project_records', project_id=project_id))
        
        # Combine all record texts for analysis
        record_texts = [record.extracted_text for record in records if record.extracted_text]
        document_texts = [doc.extracted_text for doc in documents if doc.extracted_text]
        combined_text = "\n\n".join(record_texts + document_texts)
        
        if not combined_text.strip():
            flash('No extractable text found in the uploaded files. Please ensure files contain readable text.', 'warning')
            return redirect(url_for('view_project_records', project_id=project_id))
        
        # Results containers
        results = {}
        
        # Define analysis functions for parallel execution
        def analyze_entitlements():
            results['entitlements'] = analyze_project_records(combined_text)
        
        def analyze_quantum():
            results['quantum'] = assess_quantum(combined_text)
        
        def analyze_counterclaims():
            results['counterclaims'] = evaluate_counterclaims(combined_text)
        
        def analyze_claims():
            contractor_name = project.contractor.username if project.contractor else "ABC Construction Ltd"
            results['claims'] = generate_claims(combined_text, contractor_name)
        
        # Execute analyses in parallel for better performance
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            futures.append(executor.submit(analyze_entitlements))
            futures.append(executor.submit(analyze_quantum))
            futures.append(executor.submit(analyze_counterclaims))
            futures.append(executor.submit(analyze_claims))
            
            # Wait for all analyses to complete
            concurrent.futures.wait(futures)
        
        # Process results and update database
        # Update entitlements
        entitlement = EntitlementCausation.query.filter_by(project_id=project_id).first()
        if entitlement:
            entitlement.findings = results.get('entitlements', '')
        else:
            entitlement = EntitlementCausation(
                project_id=project_id,
                findings=results.get('entitlements', '')
            )
            db.session.add(entitlement)
            
        # Update quantum
        quantum_result = results.get('quantum', {})
        quantum = Quantum.query.filter_by(project_id=project_id).first()
        if quantum:
            quantum.cost_estimate = quantum_result.get('cost_estimate', 0.0)
            quantum.time_impact_days = quantum_result.get('time_impact_days', 0)
            quantum.calculation_method = quantum_result.get('calculation_method', '')
        else:
            quantum = Quantum(
                project_id=project_id,
                cost_estimate=quantum_result.get('cost_estimate', 0.0),
                time_impact_days=quantum_result.get('time_impact_days', 0),
                calculation_method=quantum_result.get('calculation_method', '')
            )
            db.session.add(quantum)
        
        # Update counterclaims
        counterclaim = Counterclaim.query.filter_by(project_id=project_id).first()
        if counterclaim:
            counterclaim.counterclaim_summary = results.get('counterclaims', '')
        else:
            counterclaim = Counterclaim(
                project_id=project_id,
                counterclaim_summary=results.get('counterclaims', '')
            )
            db.session.add(counterclaim)
        
        # Update claims - delete existing and add new ones
        Claim.query.filter_by(project_id=project_id).delete()
        
        generated_claims = results.get('claims', [])
        for claim_data in generated_claims:
            try:
                # Parse the date
                from datetime import datetime
                date_notified = datetime.strptime(claim_data.get('date_notified', '2025-01-01'), '%Y-%m-%d')
                
                new_claim = Claim(
                    project_id=project_id,
                    claim_id=claim_data.get('claim_id', '001'),
                    claim_type=claim_data.get('claim_type', 'General Claim'),
                    date_notified=date_notified,
                    claimant=claim_data.get('claimant', project.contractor.username if project.contractor else "ABC Construction Ltd"),
                    description=claim_data.get('description', 'No description available'),
                    reference_documents=claim_data.get('reference_documents', ''),
                    status=claim_data.get('status', 'Pending'),
                    amount_claimed=claim_data.get('amount_claimed'),
                    time_extension_requested=claim_data.get('time_extension_requested'),
                    remarks=claim_data.get('remarks', ''),
                    created_by=current_user.id
                )
                db.session.add(new_claim)
            except Exception as e:
                app.logger.error(f"Error creating claim: {str(e)}")
                continue
        
        # Optimize contract risk analysis - use smarter chunking
        if documents:
            # Delete existing risks for this project (we'll regenerate from all perspectives)
            Risk.query.filter_by(project_id=project_id).delete()
            
            roles_to_analyze = ['owner', 'contractor']
            
            # Process documents efficiently with optimized chunking
            for doc in documents:
                if doc.extracted_text:
                    # Use efficient chunking strategy
                    text_chunks = chunk_text(doc.extracted_text, max_chunk_size=4000)  # Larger chunks for efficiency
                    
                    # Process roles in parallel for each document
                    def process_role_risks(role, chunks, doc_id):
                        role_risks = []
                        for chunk in chunks:
                            risks = analyze_contract_risks(chunk, role)
                            for risk_data in risks:
                                risk = Risk(
                                    document_id=doc_id,
                                    project_id=project_id,
                                    clause_text=risk_data['clause_text'][:500],
                                    risk_category=risk_data['risk_category'],
                                    risk_score=risk_data['risk_score'],
                                    explanation=risk_data['explanation'],
                                    user_role=role
                                )
                                role_risks.append(risk)
                        return role_risks
                    
                    # Process roles in parallel
                    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                        risk_futures = []
                        for role in roles_to_analyze:
                            future = executor.submit(process_role_risks, role, text_chunks, doc.id)
                            risk_futures.append(future)
                        
                        # Collect all risks
                        for future in concurrent.futures.as_completed(risk_futures):
                            role_risks = future.result()
                            for risk in role_risks:
                                db.session.add(risk)
        
        db.session.commit()
        flash('Analysis completed successfully! All analyses processed in parallel for optimal performance.', 'success')
        return redirect(url_for('generate_report', project_id=project_id))
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error during record analysis: {str(e)}")
        flash(f'Error during analysis: {str(e)}', 'danger')
        return redirect(url_for('view_project_records', project_id=project_id))

# Chatbot route
@app.route('/project/<int:project_id>/chat', methods=['GET', 'POST'])
@login_required
@project_access_required
def chatbot(project_id):
    project = Project.query.get_or_404(project_id)
    
    form = ChatForm()
    
    if form.validate_on_submit():
        user_message = form.message.data
        
        # Get project documents and records
        documents = Document.query.filter_by(project_id=project_id).all()
        records = ProjectRecord.query.filter_by(project_id=project_id).all()
        
        # Combine all document texts for context
        document_texts = [doc.extracted_text for doc in documents]
        record_texts = [rec.extracted_text for rec in records]
        
        context = "\n\n".join(document_texts + record_texts)
        
        # Get AI response with role-specific context
        ai_response = chat_with_documents(user_message, context, current_user.role)
        
        # Save the chat messages
        user_chat = ChatMessage(
            project_id=project_id,
            user_id=current_user.id,
            is_user=True,
            message=user_message,
            timestamp=datetime.now()
        )
        
        ai_chat = ChatMessage(
            project_id=project_id,
            user_id=current_user.id,  # Associate AI response with the user who asked
            is_user=False,
            message=ai_response,
            timestamp=datetime.now()
        )
        
        db.session.add(user_chat)
        db.session.add(ai_chat)
        db.session.commit()
        
        return redirect(url_for('chatbot', project_id=project_id))
    
    # Get chat history for this user only (user-specific chat)
    chat_messages = ChatMessage.query.filter_by(
        project_id=project_id, 
        user_id=current_user.id
    ).order_by(ChatMessage.timestamp).all()
    
    return render_template('chatbot.html', project=project, form=form, chat_messages=chat_messages)

# Report generation
@app.route('/project/<int:project_id>/report')
@login_required
@project_access_required
def generate_report(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Get role-specific data for the report
    if current_user.role == 'admin':
        # Admin sees both owner and contractor risks
        risks = Risk.query.filter_by(project_id=project_id).all()
    else:
        # Users only see risks from their perspective
        risks = Risk.query.filter_by(project_id=project_id, user_role=current_user.role).all()
    
    entitlements = EntitlementCausation.query.filter_by(project_id=project_id).all()
    quantum = Quantum.query.filter_by(project_id=project_id).first()
    counterclaims = Counterclaim.query.filter_by(project_id=project_id).all()
    claims = Claim.query.filter_by(project_id=project_id).all()
    
    # Create a temporary file for the PDF
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf', dir=app.config['REPORTS_FOLDER'])
    temp_filename = temp_file.name
    temp_file.close()
    
    # Create the PDF document in A1 portrait mode
    doc = SimpleDocTemplate(temp_filename, pagesize=A1)
    styles = getSampleStyleSheet()
    story = []
    
    # Add title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=1  # Center alignment
    )
    story.append(Paragraph(f"Project Report: {project.project_name}", title_style))
    story.append(Spacer(1, 12))
    
    # Add role-specific report perspective
    perspective_style = ParagraphStyle(
        'PerspectiveStyle',
        parent=styles['Normal'],
        fontSize=12,
        spaceAfter=20,
        alignment=1,  # Center alignment
        textColor=colors.blue
    )
    
    role_perspectives = {
        "owner": f"Owner's Perspective Report - Prepared for {current_user.username}",
        "contractor": f"Contractor's Perspective Report - Prepared for {current_user.username}",
        "admin": f"Administrative Analysis Report - Prepared for {current_user.username}"
    }
    
    perspective_text = role_perspectives.get(current_user.role, f"Project Report - Prepared for {current_user.username}")
    story.append(Paragraph(perspective_text, perspective_style))
    story.append(Spacer(1, 12))
    
    # Add classification
    story.append(Paragraph("Classification: Internal", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Add project details first
    story.append(Paragraph("Project Details", styles['Heading2']))
    story.append(Spacer(1, 12))
    
    project_data = [
        ["Project Name", project.project_name],
        ["Created At", project.created_at.strftime("%Y-%m-%d %H:%M:%S")],
        ["Owner", project.owner.username],
        ["Contractor", project.contractor.username],
        ["Status", project.status.capitalize()]
    ]
    
    project_table = Table(project_data, colWidths=[2*inch, 4*inch])
    project_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.darkgrey),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(project_table)
    story.append(Spacer(1, 20))
    
    # Add risks section
    if risks:
        story.append(Paragraph("Identified Risks", styles['Heading2']))
        story.append(Spacer(1, 12))
        
        # Create custom styles for risk table cells
        risk_cell_style = ParagraphStyle(
            'RiskCell',
            parent=styles['Normal'],
            fontSize=10,
            leading=12,
            spaceBefore=6,
            spaceAfter=6,
            alignment=0  # Left alignment
        )
        
        risk_data = [["Risk Category", "Risk Score", "Clause Text", "Explanation"]]
        for risk in risks:
            risk_data.append([
                Paragraph(risk.risk_category, risk_cell_style),
                Paragraph(str(risk.risk_score), risk_cell_style),
                Paragraph(risk.clause_text, risk_cell_style),
                Paragraph(risk.explanation, risk_cell_style)
            ])
        
        # Adjust column widths for better text wrapping
        risk_table = Table(risk_data, colWidths=[1.5*inch, 0.8*inch, 2.2*inch, 2.5*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6)
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 20))
        
        # Add role-specific risk recommendations
        story.append(Paragraph("Risk Assessment Recommendations", styles['Heading3']))
        story.append(Spacer(1, 8))
        
        recommendation_style = ParagraphStyle(
            'RecommendationStyle',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            spaceAfter=8,
            textColor=colors.black
        )
        
        high_risks = [r for r in risks if r.risk_score >= 75]
        medium_risks = [r for r in risks if 50 <= r.risk_score < 75]
        low_risks = [r for r in risks if r.risk_score < 50]
        
        role_recommendations = {
            "owner": {
                "intro": "As the project owner, focus on protecting your interests and minimizing exposure:",
                "high": "• Engage legal counsel for high-risk clauses immediately\n• Consider contract amendments to limit liability\n• Implement strict change order procedures\n• Increase project oversight and monitoring",
                "medium": "• Review insurance coverage adequacy\n• Establish clear communication protocols\n• Document all project decisions thoroughly\n• Monitor compliance with contract terms",
                "low": "• Maintain standard project management practices\n• Regular progress monitoring\n• Ensure proper documentation procedures"
            },
            "contractor": {
                "intro": "As the contractor, focus on protecting your rights and pursuing legitimate entitlements:",
                "high": "• Document all potential impacts immediately\n• Preserve claim rights through proper notice\n• Engage legal and technical experts\n• Implement comprehensive record-keeping",
                "medium": "• Monitor schedule and cost impacts closely\n• Maintain detailed daily records\n• Communicate delays and issues promptly\n• Preserve evidence of changed conditions",
                "low": "• Continue standard project execution\n• Maintain good project records\n• Follow contract notification requirements"
            },
            "admin": {
                "intro": "Administrative recommendations for balanced project management:",
                "high": "• Immediate stakeholder notification required\n• Consider dispute resolution mechanisms\n• Engage neutral expert assessment\n• Implement enhanced monitoring protocols",
                "medium": "• Increase oversight and reporting frequency\n• Review risk mitigation options\n• Consider early intervention strategies\n• Document all risk factors thoroughly",
                "low": "• Standard monitoring and reporting\n• Maintain proper documentation\n• Regular risk assessment updates"
            }
        }
        
        recommendations = role_recommendations.get(current_user.role, role_recommendations["admin"])
        
        story.append(Paragraph(recommendations["intro"], recommendation_style))
        story.append(Spacer(1, 8))
        
        if high_risks:
            story.append(Paragraph(f"High Risk Items ({len(high_risks)} identified):", styles['Heading4']))
            story.append(Paragraph(recommendations["high"], recommendation_style))
            
        if medium_risks:
            story.append(Paragraph(f"Medium Risk Items ({len(medium_risks)} identified):", styles['Heading4']))
            story.append(Paragraph(recommendations["medium"], recommendation_style))
            
        if low_risks:
            story.append(Paragraph(f"Low Risk Items ({len(low_risks)} identified):", styles['Heading4']))
            story.append(Paragraph(recommendations["low"], recommendation_style))
            
        story.append(Spacer(1, 20))
    
    # Add quantum section
    if quantum:
        story.append(Paragraph("Quantum Analysis", styles['Heading2']))
        story.append(Spacer(1, 12))
        
        # Create custom styles for quantum details
        quantum_cell_style = ParagraphStyle(
            'QuantumCell',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            spaceBefore=6,
            spaceAfter=6
        )
        
        quantum_data = [
            ["Cost Estimate", f"${quantum.cost_estimate:,.2f}"],
            ["Time Impact", f"{quantum.time_impact_days} days"]
        ]
        
        # Create the main table for cost and time impact
        quantum_table = Table(quantum_data, colWidths=[2*inch, 4*inch])
        quantum_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.darkgrey),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6)
        ]))
        story.append(quantum_table)
        story.append(Spacer(1, 12))
        
        # Add calculation method with proper formatting
        if quantum.calculation_method:
            story.append(Paragraph("Calculation Method:", styles['Heading4']))
            story.append(Spacer(1, 6))
            # Split the calculation method into paragraphs for better readability
            for paragraph in quantum.calculation_method.split('\n'):
                if paragraph.strip():
                    story.append(Paragraph(paragraph, quantum_cell_style))
                    story.append(Spacer(1, 6))
        
        story.append(Spacer(1, 20))
    
    # Add entitlements section
    if entitlements:
        story.append(Paragraph("Entitlements", styles['Heading2']))
        story.append(Spacer(1, 12))
        
        # Create styles for different markdown elements
        heading1_style = ParagraphStyle(
            'MDHeading1',
            parent=styles['Normal'],
            fontSize=14,
            leading=18,
            spaceBefore=12,
            spaceAfter=6,
            textColor=colors.black,
            fontName='Helvetica-Bold'
        )
        
        heading2_style = ParagraphStyle(
            'MDHeading2',
            parent=styles['Normal'],
            fontSize=12,
            leading=16,
            spaceBefore=10,
            spaceAfter=6,
            textColor=colors.black,
            fontName='Helvetica-Bold'
        )
        
        normal_style = ParagraphStyle(
            'MDNormal',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            spaceBefore=4,
            spaceAfter=4,
            textColor=colors.black
        )
        
        bullet_style = ParagraphStyle(
            'MDBullet',
            parent=normal_style,
            leftIndent=20,
            firstLineIndent=0,
            bulletIndent=10,
            spaceBefore=2,
            spaceAfter=2
        )
        
        # Process markdown content
        for entitlement in entitlements:
            if entitlement.findings:
                # Split content into lines
                lines = entitlement.findings.split('\n')
                current_text = ""
                
                for line in lines:
                    line = line.strip()
                    if not line:
                        if current_text:
                            story.append(Paragraph(current_text, normal_style))
                            current_text = ""
                        story.append(Spacer(1, 6))
                    elif line.startswith('# '):
                        if current_text:
                            story.append(Paragraph(current_text, normal_style))
                            current_text = ""
                        story.append(Paragraph(line[2:], heading1_style))
                    elif line.startswith('## '):
                        if current_text:
                            story.append(Paragraph(current_text, normal_style))
                            current_text = ""
                        story.append(Paragraph(line[3:], heading2_style))
                    elif line.startswith('- ') or line.startswith('* '):
                        if current_text:
                            story.append(Paragraph(current_text, normal_style))
                            current_text = ""
                        bullet_text = line[2:].replace('**', '')  # Remove markdown bold
                        story.append(Paragraph(f"• {bullet_text}", bullet_style))
                    else:
                        # Clean up markdown formatting
                        line = line.replace('**', '')  # Remove bold
                        line = line.replace('###', '').strip()  # Remove heading marks
                        if current_text:
                            current_text += " " + line
                        else:
                            current_text = line
                
                # Add any remaining text
                if current_text:
                    story.append(Paragraph(current_text, normal_style))
                
                story.append(Spacer(1, 12))
    
    # Add counterclaims section with similar markdown processing
    if counterclaims:
        story.append(Paragraph("Counterclaims", styles['Heading2']))
        story.append(Spacer(1, 12))
        
        for counterclaim in counterclaims:
            if counterclaim.counterclaim_summary:
                # Split content into lines
                lines = counterclaim.counterclaim_summary.split('\n')
                current_text = ""
                
                for line in lines:
                    line = line.strip()
                    if not line:
                        if current_text:
                            story.append(Paragraph(current_text, normal_style))
                            current_text = ""
                        story.append(Spacer(1, 6))
                    elif line.startswith('# '):
                        if current_text:
                            story.append(Paragraph(current_text, normal_style))
                            current_text = ""
                        story.append(Paragraph(line[2:], heading1_style))
                    elif line.startswith('## '):
                        if current_text:
                            story.append(Paragraph(current_text, normal_style))
                            current_text = ""
                        story.append(Paragraph(line[3:], heading2_style))
                    elif line.startswith('- ') or line.startswith('* '):
                        if current_text:
                            story.append(Paragraph(current_text, normal_style))
                            current_text = ""
                        bullet_text = line[2:].replace('**', '')  # Remove markdown bold
                        story.append(Paragraph(f"• {bullet_text}", bullet_style))
                    else:
                        # Clean up markdown formatting
                        line = line.replace('**', '')  # Remove bold
                        line = line.replace('###', '').strip()  # Remove heading marks
                        if current_text:
                            current_text += " " + line
                        else:
                            current_text = line
                
                # Add any remaining text
                if current_text:
                    story.append(Paragraph(current_text, normal_style))
                
                story.append(Spacer(1, 12))
    
    # Build the PDF
    doc.build(story)
    
    # Store the filename in the session
    session['report_filename'] = temp_filename
    
    # Pass all data to the template
    return render_template('report.html', 
                         project=project,
                         risks=risks,
                         entitlements=entitlements,
                         quantum=quantum,
                         counterclaims=counterclaims,
                         claims=claims)

@app.route('/project/<int:project_id>/report/download')
@login_required
@project_access_required
def download_report(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Get the filename from the session
    filename = session.get('report_filename')
    if not filename or not os.path.exists(filename):
        # If no file exists, generate it first
        return redirect(url_for('generate_report', project_id=project_id))
    
    try:
        # Send the file
        return send_file(
            filename,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"{project.project_name}_report.pdf"
        )
    except Exception as e:
        app.logger.error(f"Error downloading report: {str(e)}")
        flash('Error downloading report. Please try generating the report again.', 'error')
        return redirect(url_for('generate_report', project_id=project_id))
    finally:
        # Clean up the temporary file
        try:
            if os.path.exists(filename):
                os.unlink(filename)
        except Exception as e:
            app.logger.error(f"Error cleaning up temporary file: {str(e)}")

@app.route('/project/<int:project_id>/regenerate-risks', methods=['POST'])
@login_required
@project_access_required
def regenerate_risks(project_id):
    """Regenerate risk analysis from all role perspectives for existing documents"""
    project = Project.query.get_or_404(project_id)
    
    try:
        # Get all documents for this project
        documents = Document.query.filter_by(project_id=project_id).all()
        
        if not documents:
            flash('No documents found to analyze.', 'warning')
            return redirect(url_for('view_risks', project_id=project_id))
        
        # Delete all existing risks for this project
        Risk.query.filter_by(project_id=project_id).delete()
        
        roles_to_analyze = ['owner', 'contractor']
        risks_generated = 0
        
        for doc in documents:
            if doc.extracted_text:
                # Split text into chunks to handle large documents
                text_chunks = chunk_text(doc.extracted_text)
                for role in roles_to_analyze:
                    for chunk in text_chunks:
                        risks = analyze_contract_risks(chunk, role)
                        for risk_data in risks:
                            risk = Risk(
                                document_id=doc.id,
                                project_id=project_id,
                                clause_text=risk_data['clause_text'][:500],
                                risk_category=risk_data['risk_category'],
                                risk_score=risk_data['risk_score'],
                                explanation=risk_data['explanation'],
                                user_role=role
                            )
                            db.session.add(risk)
                            risks_generated += 1
        
        db.session.commit()
        flash(f'Successfully regenerated {risks_generated} risk analyses from all role perspectives!', 'success')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error regenerating risks: {str(e)}")
        flash(f'Error regenerating risk analysis: {str(e)}', 'danger')
    
    return redirect(url_for('view_risks', project_id=project_id))

# Claim management routes
@app.route('/project/<int:project_id>/claims')
@login_required
@project_access_required
def view_claims(project_id):
    project = Project.query.get_or_404(project_id)
    claims = Claim.query.filter_by(project_id=project_id).all()
    return render_template('view_claims.html', project=project, claims=claims)

@app.route('/project/<int:project_id>/claims/<int:claim_id>/letter')
@login_required
@project_access_required
def generate_claim_letter(project_id, claim_id):
    project = Project.query.get_or_404(project_id)
    claim = Claim.query.get_or_404(claim_id)
    
    # Ensure claim belongs to this project
    if claim.project_id != project_id:
        abort(403)
    
    # Create a temporary file for the PDF
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf', dir=app.config['REPORTS_FOLDER'])
    temp_filename = temp_file.name
    temp_file.close()
    
    # Create the PDF document
    doc = SimpleDocTemplate(temp_filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Add date
    story.append(Paragraph(f"Date: {datetime.now().strftime('%B %d, %Y')}", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Add subject
    subject_style = ParagraphStyle(
        'Subject',
        parent=styles['Normal'],
        fontSize=12,
        spaceAfter=12,
        fontName='Helvetica-Bold'
    )
    story.append(Paragraph(f"Subject: Formal Claim for {claim.claim_type} - Claim ID: {claim.claim_id}", subject_style))
    story.append(Spacer(1, 12))
    
    # Add greeting
    story.append(Paragraph("Dear Sir/Madam,", styles['Normal']))
    story.append(Spacer(1, 12))
    
    # Add main content
    content = f"""We hereby submit this formal claim regarding {claim.description}."""
    story.append(Paragraph(content, styles['Normal']))
    story.append(Spacer(1, 12))
    
    story.append(Paragraph("Details of the claim are as follows:", styles['Normal']))
    story.append(Spacer(1, 12))
    
    # Add claim details
    story.append(Paragraph("<b>1. Description of Event:</b>", styles['Normal']))
    story.append(Paragraph(claim.description, styles['Normal']))
    story.append(Spacer(1, 8))
    
    story.append(Paragraph("<b>2. Date of Event:</b>", styles['Normal']))
    story.append(Paragraph(claim.date_notified.strftime('%B %d, %Y'), styles['Normal']))
    story.append(Spacer(1, 8))
    
    story.append(Paragraph("<b>3. Impact Assessment:</b>", styles['Normal']))
    impact_items = []
    if claim.time_extension_requested:
        impact_items.append(f"Time extension required: {claim.time_extension_requested} calendar days")
    if claim.amount_claimed:
        impact_items.append(f"Additional cost incurred: USD ${claim.amount_claimed:,.2f}")
    
    if impact_items:
        for item in impact_items:
            story.append(Paragraph(f"• {item}", styles['Normal']))
    else:
        story.append(Paragraph("Impact assessment to be determined based on further analysis.", styles['Normal']))
    story.append(Spacer(1, 8))
    
    story.append(Paragraph("<b>4. Supporting Documentation:</b>", styles['Normal']))
    if claim.reference_documents:
        docs = claim.reference_documents.split(',')
        for document in docs:
            story.append(Paragraph(f"• {document.strip()}", styles['Normal']))
    else:
        story.append(Paragraph("Supporting documents are available upon request.", styles['Normal']))
    story.append(Spacer(1, 12))
    
    # Add closing
    story.append(Paragraph("We request your acknowledgement of this claim and look forward to your response.", styles['Normal']))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Thank you for your attention to this matter.", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Add signature block
    story.append(Paragraph("Yours sincerely,", styles['Normal']))
    story.append(Spacer(1, 30))
    story.append(Paragraph("_________________________", styles['Normal']))
    story.append(Paragraph("Project Manager", styles['Normal']))
    story.append(Paragraph(f"Project: {project.project_name}", styles['Normal']))
    
    # Build the PDF
    doc.build(story)
    
    try:
        # Send the file
        return send_file(
            temp_filename,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"Claim_{claim.claim_id}_Letter.pdf"
        )
    except Exception as e:
        app.logger.error(f"Error downloading claim letter: {str(e)}")
        flash('Error downloading claim letter. Please try again.', 'error')
        return redirect(url_for('view_claims', project_id=project_id))
    finally:
        # Clean up the temporary file
        try:
            if os.path.exists(temp_filename):
                os.unlink(temp_filename)
        except Exception as e:
            app.logger.error(f"Error cleaning up temporary file: {str(e)}")

@app.route('/project/<int:project_id>/download-claims-summary')
@login_required
@project_access_required
def download_claims_summary(project_id):
    project = Project.query.get_or_404(project_id)
    claims = Claim.query.filter_by(project_id=project_id).all()
    
    if not claims:
        flash('No claims found to generate summary report.', 'warning')
        return redirect(url_for('generate_report', project_id=project_id))
    
    # Create a temporary file for the PDF
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf', dir=app.config['REPORTS_FOLDER'])
    temp_filename = temp_file.name
    temp_file.close()
    
    # Create the PDF document in A1 portrait mode
    doc = SimpleDocTemplate(temp_filename, pagesize=A1)
    styles = getSampleStyleSheet()
    story = []
    
    # Add title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=28,
        spaceAfter=40,
        alignment=1  # Center alignment
    )
    story.append(Paragraph(f"Claims Summary Report", title_style))
    story.append(Paragraph(f"Project: {project.project_name}", styles['Heading2']))
    story.append(Spacer(1, 30))
    
    # Add generation date
    story.append(Paragraph(f"Generated on: {datetime.now().strftime('%B %d, %Y')}", styles['Normal']))
    story.append(Spacer(1, 30))
    
    # Create claims table in table format
    story.append(Paragraph("Claims Summary Table", styles['Heading2']))
    story.append(Spacer(1, 20))
    
    # Create custom styles for claims table cells
    claims_cell_style = ParagraphStyle(
        'ClaimsCell',
        parent=styles['Normal'],
        fontSize=11,
        leading=13,
        spaceBefore=4,
        spaceAfter=4,
        alignment=0  # Left alignment
    )
    
    # Create table headers
    claims_headers = ["#", "Claim ID", "Type", "Date", "Claimant", "Description", "Ref. Docs", "Status", "Amount (USD)", "Time Ext.", "Remarks"]
    
    # Column widths for A3 portrait - more space available
    col_widths = [0.8*inch, 1.2*inch, 1.8*inch, 1.2*inch, 1.5*inch, 2.5*inch, 2.0*inch, 1.2*inch, 1.5*inch, 1.0*inch, 2.0*inch]
    
    claims_data = [claims_headers]
    
    for i, claim in enumerate(claims, 1):
        # Process reference documents
        ref_docs = ""
        if claim.reference_documents:
            # Keep full text since we have more space in A3
            ref_docs = claim.reference_documents
        else:
            ref_docs = "N/A"
        
        claims_row = [
            Paragraph(str(i), claims_cell_style),
            Paragraph(claim.claim_id, claims_cell_style),
            Paragraph(claim.claim_type, claims_cell_style),
            Paragraph(claim.date_notified.strftime('%d-%b-%Y'), claims_cell_style),
            Paragraph(claim.claimant, claims_cell_style),
            Paragraph(claim.description, claims_cell_style),  # Full description since we have space
            Paragraph(ref_docs, claims_cell_style),
            Paragraph(claim.status, claims_cell_style),
            Paragraph(f"${claim.amount_claimed:,.2f}" if claim.amount_claimed else "N/A", claims_cell_style),
            Paragraph(f"{claim.time_extension_requested} days" if claim.time_extension_requested else "N/A", claims_cell_style),
            Paragraph(claim.remarks or "N/A", claims_cell_style)
        ]
        claims_data.append(claims_row)
    
    # Create the claims table
    claims_table = Table(claims_data, colWidths=col_widths)
    claims_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkgrey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6)
    ]))
    story.append(claims_table)
    story.append(Spacer(1, 30))
    
    # Build the PDF
    doc.build(story)
    
    try:
        # Send the file
        return send_file(
            temp_filename,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"{project.project_name}_Claims_Summary.pdf"
        )
    except Exception as e:
        app.logger.error(f"Error downloading claims summary: {str(e)}")
        flash('Error downloading claims summary. Please try again.', 'error')
        return redirect(url_for('generate_report', project_id=project_id))
    finally:
        # Clean up the temporary file
        try:
            if os.path.exists(temp_filename):
                os.unlink(temp_filename)
        except Exception as e:
            app.logger.error(f"Error cleaning up temporary file: {str(e)}")

@app.route('/project/<int:project_id>/download-risks-report')
@login_required
@project_access_required
def download_risks_report(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Get role-specific risks for the report
    if current_user.role == 'admin':
        # Admin sees both owner and contractor risks
        risks = Risk.query.filter_by(project_id=project_id).all()
    else:
        # Users only see risks from their perspective
        risks = Risk.query.filter_by(project_id=project_id, user_role=current_user.role).all()
    
    if not risks:
        flash('No risks found to generate report.', 'warning')
        return redirect(url_for('view_risks', project_id=project_id))
    
    # Create a temporary file for the PDF
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf', dir=app.config['REPORTS_FOLDER'])
    temp_filename = temp_file.name
    temp_file.close()
    
    # Create the PDF document in portrait mode
    doc = SimpleDocTemplate(temp_filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Add title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=20,
        spaceAfter=30,
        alignment=1  # Center alignment
    )
    story.append(Paragraph(f"Risk Analysis Report", title_style))
    story.append(Paragraph(f"Project: {project.project_name}", styles['Heading2']))
    story.append(Spacer(1, 20))
    
    # Add role-specific report perspective
    if current_user.role == 'admin':
        perspective = "Comprehensive risk analysis from all perspectives"
    else:
        perspective = f"Risk analysis from {current_user.role.title()}'s perspective"
    
    story.append(Paragraph(perspective, styles['Normal']))
    story.append(Paragraph(f"Generated on: {datetime.now().strftime('%B %d, %Y')}", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Risk Summary
    story.append(Paragraph("Risk Summary", styles['Heading2']))
    story.append(Spacer(1, 12))
    
    # Risk level breakdown
    high_risks = [r for r in risks if r.risk_score >= 75]
    medium_risks = [r for r in risks if 50 <= r.risk_score < 75]
    low_risks = [r for r in risks if 25 <= r.risk_score < 50]
    minimal_risks = [r for r in risks if r.risk_score < 25]
    
    summary_data = [
        ["Risk Level", "Count", "Percentage"],
        ["High Risk (75-100)", str(len(high_risks)), f"{len(high_risks)/len(risks)*100:.1f}%"],
        ["Medium Risk (50-74)", str(len(medium_risks)), f"{len(medium_risks)/len(risks)*100:.1f}%"],
        ["Low Risk (25-49)", str(len(low_risks)), f"{len(low_risks)/len(risks)*100:.1f}%"],
        ["Minimal Risk (0-24)", str(len(minimal_risks)), f"{len(minimal_risks)/len(risks)*100:.1f}%"],
        ["Total Risks", str(len(risks)), "100%"]
    ]
    
    summary_table = Table(summary_data, colWidths=[2.5*inch, 1*inch, 1.5*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkgrey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, -1), (-1, -1), colors.lightgrey),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6)
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))
    
    # Detailed Risk Analysis in Table Format
    story.append(Paragraph("Detailed Risk Analysis", styles['Heading2']))
    story.append(Spacer(1, 12))
    
    # Sort risks by score (highest first)
    sorted_risks = sorted(risks, key=lambda x: x.risk_score, reverse=True)
    
    # Create custom styles for risk table cells
    risk_cell_style = ParagraphStyle(
        'RiskCell',
        parent=styles['Normal'],
        fontSize=9,
        leading=11,
        spaceBefore=4,
        spaceAfter=4,
        alignment=0  # Left alignment
    )
    
    # Create table headers
    if current_user.role == 'admin':
        risk_headers = ["Risk Category", "Score", "Perspective", "Source Document", "Clause Text", "Explanation"]
        col_widths = [1.2*inch, 0.7*inch, 0.8*inch, 1.2*inch, 1.6*inch, 1.5*inch]
    else:
        risk_headers = ["Risk Category", "Score", "Source Document", "Clause Text", "Explanation"]
        col_widths = [1.3*inch, 0.7*inch, 1.2*inch, 1.8*inch, 2.0*inch]
    
    risk_data = [risk_headers]
    
    for risk in sorted_risks:
        if current_user.role == 'admin':
            risk_row = [
                Paragraph(risk.risk_category, risk_cell_style),
                Paragraph(str(risk.risk_score), risk_cell_style),
                Paragraph(risk.user_role.title(), risk_cell_style),
                Paragraph(risk.document.filename, risk_cell_style),
                Paragraph(risk.clause_text[:200] + "..." if len(risk.clause_text) > 200 else risk.clause_text, risk_cell_style),
                Paragraph(risk.explanation[:250] + "..." if len(risk.explanation) > 250 else risk.explanation, risk_cell_style)
            ]
        else:
            risk_row = [
                Paragraph(risk.risk_category, risk_cell_style),
                Paragraph(str(risk.risk_score), risk_cell_style),
                Paragraph(risk.document.filename, risk_cell_style),
                Paragraph(risk.clause_text[:250] + "..." if len(risk.clause_text) > 250 else risk.clause_text, risk_cell_style),
                Paragraph(risk.explanation[:300] + "..." if len(risk.explanation) > 300 else risk.explanation, risk_cell_style)
            ]
        risk_data.append(risk_row)
    
    # Create the risks table
    risk_table = Table(risk_data, colWidths=col_widths)
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkgrey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4)
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 20))
    
    # Build the PDF
    doc.build(story)
    
    try:
        # Send the file
        return send_file(
            temp_filename,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"{project.project_name}_Risk_Analysis.pdf"
        )
    except Exception as e:
        app.logger.error(f"Error downloading risks report: {str(e)}")
        flash('Error downloading risks report. Please try again.', 'error')
        return redirect(url_for('view_risks', project_id=project_id))
    finally:
        # Clean up the temporary file
        try:
            if os.path.exists(temp_filename):
                os.unlink(temp_filename)
        except Exception as e:
            app.logger.error(f"Error cleaning up temporary file: {str(e)}")

@app.route('/project/<int:project_id>/find-document')
@login_required
@project_access_required
def find_document_by_name(project_id):
    project = Project.query.get_or_404(project_id)
    filename = request.args.get('filename', '').strip()
    
    app.logger.info(f"Searching for filename: '{filename}' in project {project_id}")
    
    if not filename:
        return jsonify({"found": False, "message": "No filename provided"})
    
    # Try to find a document with exact filename match
    document = Document.query.filter_by(project_id=project_id, filename=filename).first()
    app.logger.info(f"Document exact match search result: {document}")
    
    if document:
        return jsonify({
            "found": True, 
            "document_id": document.id,
            "filename": document.filename,
            "file_type": "contract",
            "view_url": url_for('view_document', project_id=project_id, document_id=document.id),
            "download_url": url_for('download_document', project_id=project_id, document_id=document.id)
        })
    
    # Try to find a project record with exact filename match
    record = ProjectRecord.query.filter_by(project_id=project_id, filename=filename).first()
    app.logger.info(f"Record exact match search result: {record}")
    
    if record:
        return jsonify({
            "found": True,
            "record_id": record.id,
            "filename": record.filename,
            "file_type": "record",
            "record_type": record.record_type,
            "download_url": url_for('download_record', project_id=project_id, record_id=record.id)
        })
    
    # Try partial match if exact match fails
    documents = Document.query.filter_by(project_id=project_id).all()
    records = ProjectRecord.query.filter_by(project_id=project_id).all()
    
    app.logger.info(f"Found {len(documents)} documents and {len(records)} records for partial matching")
    if documents:
        app.logger.info(f"Document filenames: {[d.filename for d in documents]}")
    if records:
        app.logger.info(f"Record filenames: {[r.filename for r in records]}")
    
    partial_matches = []
    
    # Improved matching algorithm
    search_terms = filename.lower().replace('–', '-').replace('—', '-')
    
    # Extract key words from the search term, removing common words
    common_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'from', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may', 'might', 'must', 'can', 'project', 'document', 'file'}
    search_keywords = [word.strip('.,!?;:"()[]{}') for word in search_terms.split() if len(word) > 2 and word.lower() not in common_words]
    
    app.logger.info(f"Search keywords extracted: {search_keywords}")
    
    # Check documents for improved partial matches
    for doc in documents:
        doc_filename_lower = doc.filename.lower()
        match_score = 0
        
        # Simple partial matching (original logic)
        if filename.lower() in doc_filename_lower or doc_filename_lower in filename.lower():
            match_score = 100
        
        # Keyword-based matching
        elif search_keywords:
            keyword_matches = 0
            for keyword in search_keywords:
                if keyword.lower() in doc_filename_lower:
                    keyword_matches += 1
            
            if keyword_matches > 0:
                match_score = (keyword_matches / len(search_keywords)) * 80
        
        # Contract-specific smart matching
        contract_terms = ['contract', 'agreement', 'construction', 'building']
        delay_terms = ['delay', 'notification', 'notice', 'extension', 'time']
        
        if any(term in search_terms for term in contract_terms) and any(term in doc_filename_lower for term in contract_terms):
            match_score = max(match_score, 70)
        
        if any(term in search_terms for term in delay_terms) and any(term in doc_filename_lower for term in delay_terms):
            match_score = max(match_score, 70)
        
        if match_score > 30:  # Lower threshold for smarter matching
            app.logger.info(f"Document match: '{doc.filename}' scored {match_score} for search '{filename}'")
            partial_matches.append({
                "document_id": doc.id,
                "filename": doc.filename,
                "file_type": "contract",
                "match_score": match_score,
                "view_url": url_for('view_document', project_id=project_id, document_id=doc.id),
                "download_url": url_for('download_document', project_id=project_id, document_id=doc.id)
            })
    
    # Check project records for improved partial matches
    for rec in records:
        rec_filename_lower = rec.filename.lower()
        rec_type_lower = rec.record_type.lower() if rec.record_type else ''
        combined_text = f"{rec_filename_lower} {rec_type_lower}"
        match_score = 0
        
        # Simple partial matching (original logic)
        if filename.lower() in combined_text or any(part in combined_text for part in filename.lower().split()):
            match_score = 100
        
        # Keyword-based matching
        elif search_keywords:
            keyword_matches = 0
            for keyword in search_keywords:
                if keyword.lower() in combined_text:
                    keyword_matches += 1
            
            if keyword_matches > 0:
                match_score = (keyword_matches / len(search_keywords)) * 80
        
        # Record-specific smart matching
        if any(term in search_terms for term in delay_terms) and any(term in combined_text for term in delay_terms):
            match_score = max(match_score, 75)
        
        # Email/correspondence matching
        email_terms = ['email', 'letter', 'correspondence', 'notification', 'notice']
        if any(term in search_terms for term in email_terms) and any(term in combined_text for term in email_terms):
            match_score = max(match_score, 65)
        
        if match_score > 30:  # Lower threshold for smarter matching
            app.logger.info(f"Record match: '{rec.filename}' ({rec.record_type}) scored {match_score} for search '{filename}'")
            partial_matches.append({
                "record_id": rec.id,
                "filename": rec.filename,
                "file_type": "record",
                "record_type": rec.record_type,
                "match_score": match_score,
                "download_url": url_for('download_record', project_id=project_id, record_id=rec.id)
            })
    
    # Sort matches by score (highest first)
    partial_matches.sort(key=lambda x: x.get('match_score', 0), reverse=True)
    
    app.logger.info(f"Found {len(partial_matches)} matches after improved matching algorithm")
    
    if partial_matches:
        return jsonify({
            "found": True,
            "exact_match": False,
            "matches": partial_matches
        })
    
    return jsonify({"found": False, "message": f"Document '{filename}' not found in project documents or records"})

# Add this debug route before the final app.run section

@app.route('/project/<int:project_id>/debug-files')
@login_required
@project_access_required
def debug_project_files(project_id):
    """Debug route to see all files in project"""
    project = Project.query.get_or_404(project_id)
    documents = Document.query.filter_by(project_id=project_id).all()
    records = ProjectRecord.query.filter_by(project_id=project_id).all()
    
    debug_info = {
        "project_name": project.project_name,
        "project_id": project_id,
        "documents": [
            {
                "id": doc.id,
                "filename": doc.filename,
                "document_type": doc.document_type,
                "uploaded_at": doc.uploaded_at.isoformat() if doc.uploaded_at else None
            } for doc in documents
        ],
        "records": [
            {
                "id": rec.id,
                "filename": rec.filename,
                "record_type": rec.record_type,
                "uploaded_at": rec.uploaded_at.isoformat() if rec.uploaded_at else None
            } for rec in records
        ]
    }
    
    return jsonify(debug_info)

# Run the application
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
