import os
import json
import textwrap
from openai import OpenAI
from dotenv import load_dotenv

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

def analyze_contract_risks(contract_text):
    """
    Analyze contract text for risk clauses.
    
    Args:
        contract_text (str): Text extracted from contract document
        
    Returns:
        list: List of dicts containing risks (clause_text, risk_category, risk_score, explanation)
    """
    if not contract_text or not contract_text.strip():
        return []
    
    try:
        prompt = f"""
        You are a construction contract risk analyst with expertise in construction law and claims management. Thoroughly analyze this construction contract text to identify clauses that pose risks to the contractor.
        
        Identify clauses related to these risk categories (and any other relevant categories you identify):
        - Delay: Clauses that impose strict deadlines, penalties for delays, or unreasonable time constraints
        - Disruption: Clauses that could lead to disruption claims or impede contractor workflow
        - Payment: Terms that could affect timely payment, retention, cash flow, or payment security
        - Liquidated Damages: Specific penalties or damages for non-performance or delay
        - Termination: Unfavorable or one-sided termination clauses or procedures
        - Scope Change: Restrictive change order procedures, ambiguous scope definitions, or owner-directed changes
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
        3. Assign a risk score (0-100, with higher scores indicating greater risk):
           - 75-100: High risk (significant financial/legal exposure, requires immediate attention)
           - 50-74: Medium risk (substantial concerns, should be addressed or negotiated)
           - 25-49: Low risk (some concerns, but potentially manageable)
           - 0-24: Minimal risk (standard terms, limited concern)
        4. Provide a detailed explanation of why it's risky, including:
           - Potential financial impact
           - Legal implications
           - Practical consequences for project execution
           - Recommended mitigation strategies
        
        BE EXTREMELY THOROUGH - Construction contracts often contain hidden risks that may seem standard but can have significant implications. Look for:
        - Non-standard language variations of common clauses
        - One-sided provisions favoring the owner
        - Subtle shifts of risk to the contractor
        - Ambiguous language that could be exploited
        - Requirements that exceed industry standards
        - Provisions that conflict with other contract terms
        
        Format your response as a JSON object with a "risks" array containing objects with these fields:
        - clause_text: The exact text from the contract (up to 500 chars)
        - risk_category: The category from the list above
        - risk_score: Integer from 0-100
        - explanation: Detailed explanation of the risk
        
        Contract Text:
        {contract_text}
        """
        
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            temperature=0.3
        )
        
        result = json.loads(response.choices[0].message.content)
        
        # Extract risks from result
        if "risks" in result:
            return result["risks"]
        elif isinstance(result, list):
            return result
        else:
            return []
            
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
    
    # Truncate text if it's too long to avoid API timeout
    max_chars = 15000
    if len(record_text) > max_chars:
        record_text = record_text[:max_chars] + "... [text truncated for analysis]"
    
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
        {record_text}
        """
        
        # Set timeout to avoid hanging requests
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
    
    # Truncate text if it's too long to avoid API timeout
    max_chars = 15000
    if len(record_text) > max_chars:
        record_text = record_text[:max_chars] + "... [text truncated for analysis]"
    
    try:
        prompt = f"""
        Using change orders, invoices, and project records, estimate total financial quantum of claims and time impact delays.
        
        Provide your response as JSON with:
        - cost_estimate: Dollar amount (numeric value only, no $ or commas)
        - time_impact_days: Number of days (integer)
        - calculation_method: Explanation of how you calculated these values
        
        If the provided records are insufficient, use reasonable assumptions but clearly state them.
        
        Project Records:
        {record_text}
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
    
    # Truncate text if it's too long to avoid API timeout
    max_chars = 15000
    if len(record_text) > max_chars:
        record_text = record_text[:max_chars] + "... [text truncated for analysis]"
    
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
        {record_text}
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
        print(f"Error evaluating counterclaims: {str(e)}")
        error_msg = str(e)
        if "timeout" in error_msg.lower():
            return "Analysis timed out. The project records may be too complex or voluminous. Try uploading more focused records or contact support."
        return f"Error evaluating counterclaims: {error_msg[:100]}... Please try again later."

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

def chat_with_documents(user_message, context):
    """
    Allow users to chat with an AI assistant using project documents as context.
    
    Args:
        user_message (str): User's query
        context (str): Text extracted from project documents
        
    Returns:
        str: AI response
    """
    if not context or not context.strip():
        context = "No project documents available for reference."
    
    try:
        # Truncate context if it's too long
        max_chars = 10000
        if len(context) > max_chars:
            context = context[:max_chars] + "...[truncated due to length]"
            
        prompt = f"""
        You are an AI assistant for a construction claims management system. Answer the user's question 
        based only on the provided project document context. If you cannot find the answer in the 
        provided context, clearly state that you don't have enough information to answer accurately.
        
        Project Document Context:
        {context}
        
        User Question:
        {user_message}
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
