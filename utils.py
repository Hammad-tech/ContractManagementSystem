import os
import fitz  # PyMuPDF
import docx
import re
from io import BytesIO

def allowed_file(filename):
    """Check if the uploaded file has an allowed extension."""
    ALLOWED_EXTENSIONS = {'pdf', 'docx', 'doc', 'txt'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_pdf(file_path):
    """Extract text from a PDF file."""
    try:
        doc = fitz.open(file_path)
        text = ""
        for page in doc:
            text += page.get_text()
        return text
    except Exception as e:
        raise Exception(f"Error extracting text from PDF: {str(e)}")

def extract_text_from_docx(file_path):
    """Extract text from a DOCX file."""
    try:
        doc = docx.Document(file_path)
        full_text = []
        for para in doc.paragraphs:
            full_text.append(para.text)
        return '\n'.join(full_text)
    except Exception as e:
        raise Exception(f"Error extracting text from DOCX: {str(e)}")

def extract_text_from_txt(file_path):
    """Extract text from a TXT file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()
    except UnicodeDecodeError:
        # Try with a different encoding if UTF-8 fails
        with open(file_path, 'r', encoding='latin-1') as file:
            return file.read()
    except Exception as e:
        raise Exception(f"Error extracting text from TXT: {str(e)}")

def extract_text_from_file(file_path):
    """Extract text from a file based on its extension."""
    try:
        file_extension = os.path.splitext(file_path)[1].lower()
        
        if file_extension == '.pdf':
            return extract_text_from_pdf(file_path)
        elif file_extension in ['.docx', '.doc']:
            return extract_text_from_docx(file_path)
        elif file_extension == '.txt':
            return extract_text_from_txt(file_path)
        else:
            raise ValueError(f"Unsupported file format: {file_extension}")
    except Exception as e:
        raise Exception(f"Error extracting text: {str(e)}")

def format_currency(amount):
    """Format a float as currency."""
    if amount is None:
        return "$0.00"
    return f"${amount:,.2f}"

def format_date(date_obj):
    """Format a datetime object as a string."""
    if date_obj is None:
        return ""
    return date_obj.strftime("%B %d, %Y")

def truncate_text(text, max_length=100):
    """Truncate text to a specified maximum length."""
    if text is None:
        return ""
    if len(text) <= max_length:
        return text
    return text[:max_length] + "..."

def get_risk_level_class(risk_score):
    """Return Bootstrap class for risk level based on score."""
    if risk_score >= 75:
        return "danger"
    elif risk_score >= 50:
        return "warning"
    elif risk_score >= 25:
        return "info"
    else:
        return "success"

def get_risk_level_text(risk_score):
    """Return risk level text based on score."""
    if risk_score >= 75:
        return "High"
    elif risk_score >= 50:
        return "Medium"
    elif risk_score >= 25:
        return "Low"
    else:
        return "Minimal"
