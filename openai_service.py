import os
import json
import textwrap
from openai import OpenAI
from dotenv import load_dotenv
import hashlib
import pickle
import tempfile

# Load environment variables from .env file
load_dotenv()

# Get OpenAI API key from environment variable
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY environment variable is not set. Please ensure you have a .env file with OPENAI_API_KEY=your_api_key")

# Initialize OpenAI client with minimal configuration
client = OpenAI(api_key=OPENAI_API_KEY)

# Using GPT-4 Turbo as the model
OPENAI_MODEL = "gpt-4o"

# Simple in-memory cache for this session
_analysis_cache = {}

def get_cache_key(text, analysis_type, role=None):
    """Generate a cache key for analysis results"""
    content = f"{analysis_type}:{role}:{text}"
    return hashlib.md5(content.encode()).hexdigest()

def get_cached_result(cache_key):
    """Get cached analysis result"""
    return _analysis_cache.get(cache_key)

def cache_result(cache_key, result):
    """Cache analysis result"""
    _analysis_cache[cache_key] = result
    # Limit cache size to prevent memory issues
    if len(_analysis_cache) > 100:
        # Remove oldest entries
        keys_to_remove = list(_analysis_cache.keys())[:50]
        for key in keys_to_remove:
            del _analysis_cache[key]

def preprocess_text(text):
    """Optimize text for faster processing while maintaining quality"""
    if not text:
        return ""
    
    # Remove excessive whitespace and normalize
    import re
    text = re.sub(r'\s+', ' ', text.strip())
    
    # Remove duplicate paragraphs (common in extracted text)
    paragraphs = text.split('\n\n')
    unique_paragraphs = []
    seen = set()
    for para in paragraphs:
        para_key = para.strip()[:100]  # Use first 100 chars as key
        if para_key not in seen and len(para.strip()) > 10:
            unique_paragraphs.append(para)
            seen.add(para_key)
    
    return '\n\n'.join(unique_paragraphs)

def chunk_text(text, max_chunk_size=3000):
    """Break text into chunks of maximum token size."""
    # Simple approach: split by newlines first, then by spaces if needed
    if not text:
        return []
    
    lines = text.split('\n')
    chunks = []
    current_chunk = ""
    
    for line in lines:
        if len(current_chunk) + len(line) <= max_chunk_size:
            current_chunk += line + '\n'
        else:
            # If the current line is too long, split it further
            if len(line) > max_chunk_size:
                words = line.split()
                for word in words:
                    if len(current_chunk) + len(word) <= max_chunk_size:
                        current_chunk += word + ' '
                    else:
                        chunks.append(current_chunk)
                        current_chunk = word + ' '
            else:
                # Add the current chunk to chunks and start a new one
                chunks.append(current_chunk)
                current_chunk = line + '\n'
    
    # Add the last chunk if it has content
    if current_chunk:
        chunks.append(current_chunk)
    
    return chunks

def analyze_contract_risks(contract_text, user_role="contractor"):
    """
    Analyze contract text for risk clauses with role-specific perspective.
    
    Args:
        contract_text (str): Text extracted from contract document
        user_role (str): Role of the user requesting analysis ('owner', 'contractor', or 'admin')
        
    Returns:
        list: List of dicts containing risks (clause_text, risk_category, risk_score, explanation)
    """
    if not contract_text or not contract_text.strip():
        return []
    
    # Preprocess text for better performance
    processed_text = preprocess_text(contract_text)
    
    # Check cache first
    cache_key = get_cache_key(processed_text, "contract_risks", user_role)
    cached_result = get_cached_result(cache_key)
    if cached_result is not None:
        return cached_result
    
    try:
        # Role-specific analysis prompts
        role_context = {
            "owner": """
            You are analyzing this contract from an OWNER's perspective. Focus on:
            - Clauses that could expose the owner to additional liability or costs
            - Terms that favor the contractor unfairly
            - Provisions that limit the owner's rights or remedies
            - Clauses that could lead to cost overruns or schedule delays for the owner
            - Insurance and indemnification gaps that expose the owner
            - Quality control and performance standard weaknesses
            """,
            
            "contractor": """
            You are analyzing this contract from a CONTRACTOR's perspective. Focus on:
            - Clauses that impose unreasonable risks or penalties on the contractor
            - Terms that could limit the contractor's ability to recover costs
            - Provisions that expose the contractor to excessive liability
            - Clauses that could impact the contractor's schedule or performance
            - Payment terms that create cash flow risks
            - Change order and scope modification limitations
            """,
            
            "admin": """
            You are providing neutral administrative analysis. Focus on:
            - All significant risks regardless of which party they affect
            - Balanced assessment of contractual provisions
            - Clauses that could lead to disputes between parties
            - Terms that deviate from industry standards
            - Provisions that create ambiguity or potential conflicts
            """
        }
        
        analysis_context = role_context.get(user_role, role_context["contractor"])
        
        prompt = f"""
        {analysis_context}
        
        You are a construction contract risk analyst with expertise in construction law and claims management. Thoroughly analyze this construction contract text to identify clauses that pose risks.
        
        Identify clauses related to these risk categories (and any other relevant categories you identify):
        - Delay: Clauses that impose strict deadlines, penalties for delays, or unreasonable time constraints
        - Disruption: Clauses that could lead to disruption claims or impede workflow
        - Payment: Terms that could affect timely payment, retention, cash flow, or payment security
        - Liquidated Damages: Specific penalties or damages for non-performance or delay
        - Termination: Unfavorable or one-sided termination clauses or procedures
        - Scope Change: Restrictive change order procedures, ambiguous scope definitions, or directed changes
        - Force Majeure: Limited relief for unforeseen events, pandemic provisions, or supply chain disruptions
        - Dispute Resolution: Unfavorable dispute resolution procedures, jurisdiction, or waiver of rights
        - Indemnification: Broad indemnification obligations or uninsurable risks
        - Site Conditions: Differing site conditions clauses, site access limitations, or site responsibility issues
        - Insurance/Bonds: Onerous insurance requirements, high bond amounts, or difficult-to-obtain coverage
        - Warranty: Extended warranty periods, unreasonable performance guarantees, or defect liability terms
        - Compliance: Regulatory compliance requirements or shifting compliance risks
        
        For each identified risk clause:
        1. Extract the exact text from the contract
        2. Categorize the risk using the categories above (or create a new category if needed)
        3. Assign a risk score (0-100, with higher scores indicating greater risk FROM THE {user_role.upper()}'S PERSPECTIVE):
           - 75-100: High risk (significant financial/legal exposure, requires immediate attention)
           - 50-74: Medium risk (substantial concerns, should be addressed or negotiated)
           - 25-49: Low risk (some concerns, but potentially manageable)
           - 0-24: Minimal risk (standard terms, limited concern)
        4. Provide a detailed explanation of why it's risky FROM THE {user_role.upper()}'S PERSPECTIVE, including:
           - Potential financial impact for the {user_role}
           - Legal implications for the {user_role}
           - Practical consequences for the {user_role}
           - Recommended mitigation strategies for the {user_role}
        
        BE EXTREMELY THOROUGH and analyze from the {user_role.upper()}'S PERSPECTIVE. The same clause may have different risk levels for different parties.
        
        Format your response as a JSON object with a "risks" array containing objects with these fields:
        - clause_text: The exact text from the contract (up to 500 chars)
        - risk_category: The category from the list above
        - risk_score: Integer from 0-100 (from {user_role}'s perspective)
        - explanation: Detailed explanation of the risk from {user_role}'s perspective
        
        Contract Text:
        {processed_text}
        """
        
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            temperature=0.3
        )
        
        result = json.loads(response.choices[0].message.content)
        
        # Extract risks from result
        risks = []
        if "risks" in result:
            risks = result["risks"]
        elif isinstance(result, list):
            risks = result
        
        # Cache the result
        cache_result(cache_key, risks)
        return risks
            
    except Exception as e:
        print(f"Error analyzing contract risks: {str(e)}")
        return []

def analyze_project_records(record_text):
    """
    Analyze project records to validate causation and entitlement.
    
    Args:
        record_text (str): Combined text from project records
        
    Returns:
        str: Findings text summarizing entitlement conclusions
    """
    if not record_text or not record_text.strip():
        return "Insufficient project records for analysis."
    
    # Preprocess text for better performance
    processed_text = preprocess_text(record_text)
    
    # Check cache first
    cache_key = get_cache_key(processed_text, "project_records")
    cached_result = get_cached_result(cache_key)
    if cached_result is not None:
        return cached_result
    
    # Keep original length for quality but optimize processing
    max_chars = 15000
    if len(processed_text) > max_chars:
        processed_text = processed_text[:max_chars] + "... [text truncated for analysis]"
    
    try:
        prompt = f"""
        Using the project daily logs, emails, and baseline schedules provided, validate whether the contractor has entitlement for delay or disruption claims.
        Provide reasoning for causation links and mitigation efforts.
        
        Your analysis should focus on:
        1. Evidence of events causing delays or disruptions
        2. Whether timely notices were provided
        3. Mitigation efforts undertaken
        4. Clear causation links between events and impacts
        
        Provide a well-structured, professional analysis of approximately 1000 words.
        If the provided records seem insufficient, clearly state what additional information would be needed.
        
        Project Records:
        {processed_text}
        """
        
        # Use parallel processing optimization
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            timeout=45  # Balanced timeout
        )
        
        if not response or not hasattr(response, 'choices') or not response.choices:
            return "Analysis failed: No valid response received from analysis engine."
            
        result = response.choices[0].message.content
        
        # Cache the result
        cache_result(cache_key, result)
        return result
        
    except Exception as e:
        print(f"Error analyzing project records: {str(e)}")
        error_msg = str(e)
        if "timeout" in error_msg.lower():
            return "Analysis timed out. The project records may be too complex or voluminous. Try uploading more focused records or contact support."
        return f"Error analyzing project records: {error_msg[:100]}... Please try again later."

def assess_quantum(record_text):
    """
    Assess quantum for cost claims and time impact.
    
    Args:
        record_text (str): Combined text from project records
        
    Returns:
        dict: Contains cost_estimate, time_impact_days, and calculation_method
    """
    if not record_text or not record_text.strip():
        return {
            "cost_estimate": 0.0,
            "time_impact_days": 0,
            "calculation_method": "No project records available for quantum assessment."
        }
    
    # Preprocess text for better performance
    processed_text = preprocess_text(record_text)
    
    # Check cache first
    cache_key = get_cache_key(processed_text, "assess_quantum")
    cached_result = get_cached_result(cache_key)
    if cached_result is not None:
        return cached_result
    
    # Truncate text if it's too long to avoid API timeout
    max_chars = 15000
    if len(processed_text) > max_chars:
        processed_text = processed_text[:max_chars] + "... [text truncated for analysis]"
    
    try:
        prompt = f"""
        Using change orders, invoices, and project records, estimate total financial quantum of claims and time impact delays.
        
        Provide your response as JSON with:
        - cost_estimate: Dollar amount (numeric value only, no $ or commas)
        - time_impact_days: Number of days (integer)
        - calculation_method: Explanation of how you calculated these values
        
        If the provided records are insufficient, use reasonable assumptions but clearly state them.
        
        Project Records:
        {processed_text}
        """
        
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            temperature=0.2,
            timeout=60  # 60-second timeout
        )
        
        result = json.loads(response.choices[0].message.content)
        
        # Ensure the response contains the expected fields
        if not isinstance(result.get("cost_estimate"), (int, float)):
            result["cost_estimate"] = 0.0
        
        if not isinstance(result.get("time_impact_days"), int):
            try:
                # Try to convert to integer if possible
                result["time_impact_days"] = int(float(result.get("time_impact_days", 0)))
            except:
                result["time_impact_days"] = 0
            
        if not isinstance(result.get("calculation_method"), str):
            result["calculation_method"] = "Method not provided"
            
        # Cache the result
        cache_result(cache_key, result)
        return result
        
    except json.JSONDecodeError as e:
        print(f"JSON decode error in quantum assessment: {str(e)}")
        return {
            "cost_estimate": 0.0,
            "time_impact_days": 0,
            "calculation_method": "Error parsing quantum assessment results. The analysis output was not in the expected format."
        }
    except Exception as e:
        print(f"Error assessing quantum: {str(e)}")
        error_msg = str(e)
        if "timeout" in error_msg.lower():
            return {
                "cost_estimate": 0.0,
                "time_impact_days": 0,
                "calculation_method": "Analysis timed out. The project records may be too complex. Try uploading more focused records."
            }
        return {
            "cost_estimate": 0.0,
            "time_impact_days": 0,
            "calculation_method": f"Error assessing quantum: {error_msg[:100]}... Please try again."
        }

def evaluate_counterclaims(record_text):
    """
    Evaluate possible counterclaims and defenses.
    
    Args:
        record_text (str): Combined text from project records
        
    Returns:
        str: Summary of counterclaims and defenses
    """
    if not record_text or not record_text.strip():
        return "Insufficient project records for counterclaim analysis."
    
    # Preprocess text for better performance
    processed_text = preprocess_text(record_text)
    
    # Check cache first
    cache_key = get_cache_key(processed_text, "evaluate_counterclaims")
    cached_result = get_cached_result(cache_key)
    if cached_result is not None:
        return cached_result
    
    # Truncate text if it's too long to avoid API timeout
    max_chars = 15000
    if len(processed_text) > max_chars:
        processed_text = processed_text[:max_chars] + "... [text truncated for analysis]"
    
    try:
        prompt = f"""
        Based on owner's correspondence and project logs, list possible counterclaims and defenses.
        
        Focus on:
        1. Concurrent delay
        2. Improper notice
        3. Failure to mitigate
        4. Other potential defenses
        
        Provide a well-structured, professional analysis of approximately 800 words, organized by counterclaim type.
        If the provided records appear insufficient, clearly state what additional information would be helpful.
        
        Project Records:
        {processed_text}
        """
        
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            timeout=60  # 60-second timeout
        )
        
        if not response or not hasattr(response, 'choices') or not response.choices:
            return "Analysis failed: No valid response received from analysis engine."
            
        result = response.choices[0].message.content
        
        # Cache the result
        cache_result(cache_key, result)
        return result
        
    except Exception as e:
        print(f"Error evaluating counterclaims: {str(e)}")
        error_msg = str(e)
        if "timeout" in error_msg.lower():
            return "Analysis timed out. The project records may be too complex or voluminous. Try uploading more focused records or contact support."
        return f"Error evaluating counterclaims: {error_msg[:100]}... Please try again later."

def generate_claims(record_text, contractor_name="ABC Construction Ltd"):
    """
    Automatically generate formal claims based on project records analysis.
    
    Args:
        record_text (str): Combined text from project records
        contractor_name (str): Name of the contracting company
        
    Returns:
        list: List of dictionaries containing claim information
    """
    if not record_text or not record_text.strip():
        return []
    
    # Preprocess text for better performance
    processed_text = preprocess_text(record_text)
    
    # Check cache first
    cache_key = get_cache_key(f"{processed_text}:{contractor_name}", "generate_claims")
    cached_result = get_cached_result(cache_key)
    if cached_result is not None:
        return cached_result
    
    # Maintain quality - keep original text processing length
    max_chars = 15000
    if len(processed_text) > max_chars:
        processed_text = processed_text[:max_chars] + "... [text truncated for analysis]"
    
    try:
        prompt = f"""
        Based on the project records and documentation provided, identify and generate formal construction claims.
        
        Analyze the records for evidence of:
        - Delay events and their causes
        - Variation/change orders
        - Weather delays and impacts
        - Payment disputes
        - Suspension of work
        - Acceleration requests
        - Subcontractor delays
        - Other compensable events
        
        For each identified claim, provide the response in JSON format as an array of objects with these fields:
        - claim_id: Sequential ID (001, 002, etc.)
        - claim_type: Type of claim (e.g., "Time Extension Claim", "Variation Claim", "Weather Delay Claim", etc.)
        - date_notified: Date when the claim was identified (use format YYYY-MM-DD, estimate based on records)
        - claimant: The contractor name (use "{contractor_name}")
        - description: Brief description of the claim event
        - reference_documents: Comma-separated list of supporting documents referenced in the records
        - status: Status of the claim (e.g., "Pending", "Active", "Disputed")
        - amount_claimed: Estimated financial amount if determinable from records (numeric value or null)
        - time_extension_requested: Days of time extension if applicable (numeric value or null)
        - remarks: Additional relevant notes or findings
        
        Only generate claims that have reasonable evidence in the provided records. If no claims can be substantiated, return an empty array.
        
        Project Records:
        {processed_text}
        """
        
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            temperature=0.3,
            timeout=45  # Balanced timeout
        )
        
        if not response or not hasattr(response, 'choices') or not response.choices:
            return []
            
        result = json.loads(response.choices[0].message.content)
        
        # Return all valid claims - maintain quality
        claims = []
        if isinstance(result, dict) and 'claims' in result:
            claims = result['claims'] if isinstance(result['claims'], list) else []
        elif isinstance(result, list):
            claims = result
        
        # Cache the result
        cache_result(cache_key, claims)
        return claims
        
    except json.JSONDecodeError as e:
        print(f"JSON decode error in claims generation: {str(e)}")
        return []
    except Exception as e:
        print(f"Error generating claims: {str(e)}")
        return []

def suggest_dispute_strategy(analysis_text):
    """
    Suggest dispute resolution strategy based on analysis.
    
    Args:
        analysis_text (str): Combined text from entitlement, quantum, and counterclaim analyses
        
    Returns:
        str: Dispute strategy recommendation
    """
    if not analysis_text or not analysis_text.strip():
        return "Insufficient analysis for dispute strategy recommendation."
    
    # Truncate text if it's too long
    max_chars = 15000
    if len(analysis_text) > max_chars:
        analysis_text = analysis_text[:max_chars] + "... [text truncated for analysis]"
    
    try:
        prompt = f"""
        Based on claim risks and counterclaims, suggest whether negotiation, ADR, or litigation is recommended.
        
        Your recommendation should include:
        1. Preferred dispute resolution approach (negotiation, mediation, arbitration, or litigation)
        2. Rationale for the recommendation
        3. Key strategic considerations
        4. Estimated timeline and cost considerations
        
        Provide a well-structured, professional recommendation of approximately 800 words.
        
        Analysis:
        {analysis_text}
        """
        
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            timeout=60  # 60-second timeout
        )
        
        if not response or not hasattr(response, 'choices') or not response.choices:
            return "Analysis failed: No valid response received from analysis engine."
            
        return response.choices[0].message.content
        
    except Exception as e:
        print(f"Error suggesting dispute strategy: {str(e)}")
        error_msg = str(e)
        if "timeout" in error_msg.lower():
            return "Analysis timed out. Please try again later or contact support."
        return f"Error suggesting dispute strategy: {error_msg[:100]}... Please try again later."

def chat_with_documents(user_message, context, user_role="contractor"):
    """
    Allow users to chat with an AI assistant using project documents as context.
    Provides role-specific advice for owners and contractors.
    
    Args:
        user_message (str): User's query
        context (str): Text extracted from project documents
        user_role (str): Role of the user ('owner', 'contractor', or 'admin')
        
    Returns:
        str: AI response tailored to the user's role
    """
    if not context or not context.strip():
        context = "No project documents available for reference."
    
    try:
        # Truncate context if it's too long
        max_chars = 10000
        if len(context) > max_chars:
            context = context[:max_chars] + "...[truncated due to length]"
        
        # Role-specific system prompts
        role_prompts = {
            "owner": """
            You are an AI assistant for project OWNERS in a construction claims management system. 
            Provide advice from the OWNER'S perspective, focusing on:
            - Protecting the owner's interests and minimizing liability
            - Contract compliance and enforcement
            - Quality control and project standards
            - Risk mitigation strategies for owners
            - Cost control and budget protection
            - Schedule adherence and delay prevention
            
            Always provide balanced, professional advice while keeping the owner's best interests in mind.
            """,
            
            "contractor": """
            You are an AI assistant for CONTRACTORS in a construction claims management system.
            Provide advice from the CONTRACTOR'S perspective, focusing on:
            - Protecting contractor rights and pursuing legitimate claims
            - Change order documentation and entitlements
            - Schedule impact analysis and delay claims
            - Cost recovery and fair compensation
            - Risk allocation and contract interpretation
            - Compliance with contract requirements while protecting contractor interests
            
            Always provide balanced, professional advice while supporting the contractor's legitimate business interests.
            """,
            
            "admin": """
            You are an AI assistant for ADMINISTRATORS in a construction claims management system.
            Provide neutral, analytical advice focusing on:
            - Objective contract analysis and interpretation
            - Risk assessment from all perspectives
            - Dispute prevention and early resolution
            - Comprehensive project management insights
            - Balanced legal and commercial considerations
            
            Maintain objectivity while providing comprehensive analysis.
            """
        }
        
        system_prompt = role_prompts.get(user_role, role_prompts["contractor"])
            
        prompt = f"""
        {system_prompt}
        
        Answer the user's question based on the provided project document context. If you cannot find 
        the answer in the provided context, clearly state that you don't have enough information to 
        answer accurately, but still provide general guidance relevant to their role when appropriate.
        
        Project Document Context:
        {context}
        
        User Question:
        {user_message}
        
        Remember to tailor your response specifically for a {user_role.upper()}'s perspective and interests.
        """
        
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            timeout=30  # 30-second timeout for better user experience
        )
        
        if not response or not hasattr(response, 'choices') or not response.choices:
            return "I'm sorry, but I couldn't generate a response at this time. Please try asking again."
            
        return response.choices[0].message.content
        
    except Exception as e:
        print(f"Error in chatbot: {str(e)}")
        error_msg = str(e)
        if "timeout" in error_msg.lower():
            return "I'm sorry, but the response timed out. Please try asking a simpler question or breaking it into multiple parts."
        return "I'm sorry, but I encountered an error while processing your request. Please try again."
