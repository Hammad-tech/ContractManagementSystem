import os
import logging
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, session, abort, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy.exc import SQLAlchemyError
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from io import BytesIO
import weasyprint
import json

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Initialize Flask app
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PROJECT_RECORDS_FOLDER'] = 'project_records'
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Create upload directories if they don't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROJECT_RECORDS_FOLDER'], exist_ok=True)

# Import models and services
from models import User, Project, Document, ProjectRecord, Risk, EntitlementCausation, Quantum, Counterclaim, ChatMessage
from forms import LoginForm, RegistrationForm, ProjectForm, UploadDocumentForm, UploadProjectRecordForm, ChatForm
from utils import extract_text_from_file, allowed_file
from openai_service import (analyze_contract_risks, analyze_project_records, 
                           assess_quantum, evaluate_counterclaims, 
                           suggest_dispute_strategy, chat_with_documents,
                           chunk_text)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Create database tables within application context
with app.app_context():
    db.create_all()

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
        user = User.query.filter_by(email=form.email.data).first()
        
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        # Check if user already exists
        existing_user = User.query.filter((User.email == form.email.data) | 
                                         (User.username == form.username.data)).first()
        
        if existing_user:
            flash('Username or email already exists', 'danger')
        else:
            # Create new user
            hashed_password = generate_password_hash(form.password.data)
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password_hash=hashed_password
            )
            
            try:
                db.session.add(new_user)
                db.session.commit()
                flash('Account created successfully! Please log in.', 'success')
                return redirect(url_for('login'))
            except SQLAlchemyError as e:
                db.session.rollback()
                app.logger.error(f"Database error: {str(e)}")
                flash('An error occurred. Please try again.', 'danger')
    
    return render_template('signup.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Project management routes
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = ProjectForm()
    
    if form.validate_on_submit():
        new_project = Project(
            user_id=current_user.id,
            project_name=form.project_name.data,
            created_at=datetime.now()
        )
        
        try:
            db.session.add(new_project)
            db.session.commit()
            flash('Project created successfully!', 'success')
            return redirect(url_for('dashboard'))
        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Database error: {str(e)}")
            flash('An error occurred. Please try again.', 'danger')
    
    projects = Project.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', projects=projects, form=form)

@app.route('/project/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the current user owns the project
    if project.user_id != current_user.id:
        abort(403)
    
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
    
    return redirect(url_for('dashboard'))

# Document management routes
@app.route('/project/<int:project_id>/upload', methods=['GET', 'POST'])
@login_required
def upload_document(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the current user owns the project
    if project.user_id != current_user.id:
        abort(403)
    
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
                    uploaded_at=datetime.now()
                )
                
                db.session.add(new_document)
                db.session.commit()
                
                # Analyze contract for risks
                chunked_text = chunk_text(extracted_text)
                for chunk in chunked_text:
                    risks = analyze_contract_risks(chunk)
                    
                    for risk in risks:
                        new_risk = Risk(
                            document_id=new_document.id,
                            project_id=project_id,
                            clause_text=risk['clause_text'],
                            risk_category=risk['risk_category'],
                            risk_score=risk['risk_score'],
                            explanation=risk['explanation']
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
                    uploaded_at=datetime.now()
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
def view_project_documents(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the current user owns the project
    if project.user_id != current_user.id:
        abort(403)
    
    documents = Document.query.filter_by(project_id=project_id).all()
    return render_template('view_project_documents.html', project=project, documents=documents)

@app.route('/project/<int:project_id>/document/<int:document_id>')
@login_required
def view_document(project_id, document_id):
    project = Project.query.get_or_404(project_id)
    document = Document.query.get_or_404(document_id)
    
    # Ensure the current user owns the project
    if project.user_id != current_user.id or document.project_id != project_id:
        abort(403)
    
    risks = Risk.query.filter_by(document_id=document_id).all()
    return render_template('view_document.html', project=project, document=document, risks=risks)

@app.route('/project/<int:project_id>/document/<int:document_id>/download')
@login_required
def download_document(project_id, document_id):
    project = Project.query.get_or_404(project_id)
    document = Document.query.get_or_404(document_id)
    
    # Ensure the current user owns the project
    if project.user_id != current_user.id or document.project_id != project_id:
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
def view_project_records(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the current user owns the project
    if project.user_id != current_user.id:
        abort(403)
    
    records = ProjectRecord.query.filter_by(project_id=project_id).all()
    return render_template('view_project_records.html', project=project, records=records)

@app.route('/project/<int:project_id>/record/<int:record_id>/download')
@login_required
def download_record(project_id, record_id):
    project = Project.query.get_or_404(project_id)
    record = ProjectRecord.query.get_or_404(record_id)
    
    # Ensure the current user owns the project
    if project.user_id != current_user.id or record.project_id != project_id:
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
def view_risks(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the current user owns the project
    if project.user_id != current_user.id:
        abort(403)
    
    risks = Risk.query.filter_by(project_id=project_id).all()
    return render_template('view_risks.html', project=project, risks=risks)

@app.route('/project/<int:project_id>/analyze-records', methods=['POST'])
@login_required
def analyze_records(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the current user owns the project
    if project.user_id != current_user.id:
        abort(403)
    
    try:
        # Get all project records
        records = ProjectRecord.query.filter_by(project_id=project_id).all()
        
        if not records:
            flash('No project records found for analysis', 'warning')
            return redirect(url_for('view_project_records', project_id=project_id))
        
        # Combine record texts for analysis
        combined_text = "\n".join([f"--- {record.record_type}: {record.filename} ---\n{record.extracted_text}" 
                                  for record in records])
        
        # Analyze for entitlement and causation
        findings = analyze_project_records(combined_text)
        
        # Save or update findings
        entitlement = EntitlementCausation.query.filter_by(project_id=project_id).first()
        
        if entitlement:
            entitlement.findings = findings
        else:
            entitlement = EntitlementCausation(
                project_id=project_id,
                findings=findings
            )
            db.session.add(entitlement)
        
        # Assess quantum
        quantum_result = assess_quantum(combined_text)
        
        # Save or update quantum
        quantum = Quantum.query.filter_by(project_id=project_id).first()
        
        if quantum:
            quantum.cost_estimate = quantum_result['cost_estimate']
            quantum.time_impact_days = quantum_result['time_impact_days']
            quantum.calculation_method = quantum_result['calculation_method']
        else:
            quantum = Quantum(
                project_id=project_id,
                cost_estimate=quantum_result['cost_estimate'],
                time_impact_days=quantum_result['time_impact_days'],
                calculation_method=quantum_result['calculation_method']
            )
            db.session.add(quantum)
        
        # Evaluate counterclaims
        counterclaim_summary = evaluate_counterclaims(combined_text)
        
        # Save or update counterclaims
        counterclaim = Counterclaim.query.filter_by(project_id=project_id).first()
        
        if counterclaim:
            counterclaim.counterclaim_summary = counterclaim_summary
        else:
            counterclaim = Counterclaim(
                project_id=project_id,
                counterclaim_summary=counterclaim_summary
            )
            db.session.add(counterclaim)
        
        db.session.commit()
        flash('Project records analyzed successfully!', 'success')
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error analyzing project records: {str(e)}")
        flash(f'Error analyzing project records: {str(e)}', 'danger')
    
    return redirect(url_for('view_project_records', project_id=project_id))

# Chatbot route
@app.route('/project/<int:project_id>/chat', methods=['GET', 'POST'])
@login_required
def chatbot(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the current user owns the project
    if project.user_id != current_user.id:
        abort(403)
    
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
        
        # Get AI response
        ai_response = chat_with_documents(user_message, context)
        
        # Save the chat messages
        user_chat = ChatMessage(
            project_id=project_id,
            is_user=True,
            message=user_message,
            timestamp=datetime.now()
        )
        
        ai_chat = ChatMessage(
            project_id=project_id,
            is_user=False,
            message=ai_response,
            timestamp=datetime.now()
        )
        
        db.session.add(user_chat)
        db.session.add(ai_chat)
        db.session.commit()
        
        return redirect(url_for('chatbot', project_id=project_id))
    
    # Get chat history
    chat_messages = ChatMessage.query.filter_by(project_id=project_id).order_by(ChatMessage.timestamp).all()
    
    return render_template('chatbot.html', project=project, form=form, chat_messages=chat_messages)

# Report generation
@app.route('/project/<int:project_id>/report')
@login_required
def generate_report(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the current user owns the project
    if project.user_id != current_user.id:
        abort(403)
    
    # Get all relevant project data
    documents = Document.query.filter_by(project_id=project_id).all()
    risks = Risk.query.filter_by(project_id=project_id).all()
    entitlement = EntitlementCausation.query.filter_by(project_id=project_id).first()
    quantum = Quantum.query.filter_by(project_id=project_id).first()
    counterclaim = Counterclaim.query.filter_by(project_id=project_id).first()
    records = ProjectRecord.query.filter_by(project_id=project_id).all()
    
    # Generate dispute strategy recommendation
    dispute_strategy = None
    
    if entitlement and quantum and counterclaim:
        combined_text = f"""
        Entitlement Findings: {entitlement.findings}
        
        Quantum Assessment: 
        Cost Estimate: ${quantum.cost_estimate}
        Time Impact: {quantum.time_impact_days} days
        
        Counterclaim Summary:
        {counterclaim.counterclaim_summary}
        """
        
        dispute_strategy = suggest_dispute_strategy(combined_text)
    
    # Add current date for the report
    current_date = datetime.now()
    
    return render_template('report.html', 
                          project=project, 
                          documents=documents, 
                          risks=risks, 
                          entitlement=entitlement, 
                          quantum=quantum, 
                          counterclaim=counterclaim,
                          records=records,
                          dispute_strategy=dispute_strategy,
                          current_date=current_date)

@app.route('/project/<int:project_id>/report/download')
@login_required
def download_report(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the current user owns the project
    if project.user_id != current_user.id:
        abort(403)
    
    # Get all relevant project data (same as generate_report)
    documents = Document.query.filter_by(project_id=project_id).all()
    risks = Risk.query.filter_by(project_id=project_id).all()
    entitlement = EntitlementCausation.query.filter_by(project_id=project_id).first()
    quantum = Quantum.query.filter_by(project_id=project_id).first()
    counterclaim = Counterclaim.query.filter_by(project_id=project_id).first()
    records = ProjectRecord.query.filter_by(project_id=project_id).all()
    
    # Generate dispute strategy recommendation
    dispute_strategy = None
    
    if entitlement and quantum and counterclaim:
        combined_text = f"""
        Entitlement Findings: {entitlement.findings}
        
        Quantum Assessment: 
        Cost Estimate: ${quantum.cost_estimate}
        Time Impact: {quantum.time_impact_days} days
        
        Counterclaim Summary:
        {counterclaim.counterclaim_summary}
        """
        
        dispute_strategy = suggest_dispute_strategy(combined_text)
    
    # Add current date for the report
    current_date = datetime.now()
    
    # Generate HTML report
    html = render_template('report.html', 
                          project=project, 
                          documents=documents, 
                          risks=risks, 
                          entitlement=entitlement, 
                          quantum=quantum, 
                          counterclaim=counterclaim,
                          records=records,
                          dispute_strategy=dispute_strategy,
                          current_date=current_date,
                          pdf_download=True)
    
    # Convert to PDF
    pdf = weasyprint.HTML(string=html).write_pdf()
    
    # Create a BytesIO object
    pdf_io = BytesIO(pdf)
    pdf_io.seek(0)
    
    # Generate filename
    filename = f"{project.project_name.replace(' ', '_')}_claim_report.pdf"
    
    return send_file(
        pdf_io,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=filename
    )

# Run the application
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
