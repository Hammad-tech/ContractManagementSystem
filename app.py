import os
import logging
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, session, abort, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy.exc import SQLAlchemyError
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import json
from dotenv import load_dotenv
import tempfile

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
        
        # Perform entitlement analysis
        entitlement_findings = analyze_project_records(combined_text)
        
        entitlement = EntitlementCausation.query.filter_by(project_id=project_id).first()
        if entitlement:
            entitlement.findings = entitlement_findings
        else:
            entitlement = EntitlementCausation(
                project_id=project_id,
                findings=entitlement_findings
            )
            db.session.add(entitlement)
            
        # Perform quantum analysis
        quantum_result = assess_quantum(combined_text)
        
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
        
        # Perform counterclaim analysis
        counterclaim_summary = evaluate_counterclaims(combined_text)
        
        counterclaim = Counterclaim.query.filter_by(project_id=project_id).first()
        if counterclaim:
            counterclaim.counterclaim_summary = counterclaim_summary
        else:
            counterclaim = Counterclaim(
                project_id=project_id,
                counterclaim_summary=counterclaim_summary
            )
            db.session.add(counterclaim)
        
        # Analyze contract risks if documents are present
        if documents:
            # First, delete existing risks for this project
            Risk.query.filter_by(project_id=project_id).delete()
            
            for doc in documents:
                if doc.extracted_text:
                    # Split text into chunks to handle large documents
                    text_chunks = chunk_text(doc.extracted_text)
                    for chunk in text_chunks:
                        risks = analyze_contract_risks(chunk)
                        for risk_data in risks:
                            risk = Risk(
                                document_id=doc.id,
                                project_id=project_id,
                                clause_text=risk_data['clause_text'][:500],  # Limit to 500 chars
                                risk_category=risk_data['risk_category'],
                                risk_score=risk_data['risk_score'],
                                explanation=risk_data['explanation']
                            )
                            db.session.add(risk)
        
        db.session.commit()
        flash('Analysis completed successfully!', 'success')
        return redirect(url_for('generate_report', project_id=project_id))
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error during record analysis: {str(e)}")
        flash(f'Error during analysis: {str(e)}', 'danger')
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
    
    # Get all data for the report
    risks = Risk.query.filter_by(project_id=project_id).all()
    entitlements = EntitlementCausation.query.filter_by(project_id=project_id).all()
    quantum = Quantum.query.filter_by(project_id=project_id).first()
    counterclaims = Counterclaim.query.filter_by(project_id=project_id).all()
    
    # Create a temporary file for the PDF
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf', dir=app.config['REPORTS_FOLDER'])
    temp_filename = temp_file.name
    temp_file.close()
    
    # Create the PDF document
    doc = SimpleDocTemplate(temp_filename, pagesize=letter)
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
    
    # Add project details
    story.append(Paragraph("Project Details", styles['Heading2']))
    story.append(Spacer(1, 12))
    
    project_data = [
        ["Project Name", project.project_name],
        ["Created At", project.created_at.strftime("%Y-%m-%d %H:%M:%S")]
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
                         counterclaims=counterclaims)

@app.route('/project/<int:project_id>/report/download')
@login_required
def download_report(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the current user owns the project
    if project.user_id != current_user.id:
        abort(403)
    
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

# Run the application
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
