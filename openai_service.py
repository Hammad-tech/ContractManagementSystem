import os
import json
import textwrap
from openai import OpenAI

# The newest OpenAI model is "gpt-4o" which was released May 13, 2024.
# Do not change this unless explicitly requested by the user
OPENAI_MODEL = "gpt-4o"

# Initialize OpenAI client
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
openai = OpenAI(api_key=OPENAI_API_KEY)

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
        From this contract text, identify risky clauses and categorize them into Delay, Disruption, Acceleration, 
        Payment, Defective Work, Scope Change, Breach, Liquidated Damages, or Termination risks.
        Assign each a risk score between 0-100 and provide an explanation.
        
        Format your response as a valid JSON array with objects containing:
        - clause_text: The exact text from the contract (up to 500 chars)
        - risk_category: One of the categories mentioned above
        - risk_score: Integer 0-100
        - explanation: Brief explanation of the risk
        
        Only include clauses that contain actual risk. Respond with an empty array if no risks are found.
        
        Contract Text:
        {contract_text}
        """
        
        response = openai.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            temperature=0.1
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
        
        Project Records:
        {record_text}
        """
        
        response = openai.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3
        )
        
        return response.choices[0].message.content
        
    except Exception as e:
        print(f"Error analyzing project records: {str(e)}")
        return "Error analyzing project records. Please try again."

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
    
    try:
        prompt = f"""
        Using change orders, invoices, and project records, estimate total financial quantum of claims and time impact delays.
        
        Provide your response as JSON with:
        - cost_estimate: Dollar amount (numeric value only, no $ or commas)
        - time_impact_days: Number of days (integer)
        - calculation_method: Explanation of how you calculated these values
        
        Project Records:
        {record_text}
        """
        
        response = openai.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            temperature=0.2
        )
        
        result = json.loads(response.choices[0].message.content)
        
        # Ensure the response contains the expected fields
        if not isinstance(result.get("cost_estimate"), (int, float)):
            result["cost_estimate"] = 0.0
        
        if not isinstance(result.get("time_impact_days"), int):
            result["time_impact_days"] = 0
            
        if not isinstance(result.get("calculation_method"), str):
            result["calculation_method"] = "Method not provided"
            
        return result
        
    except Exception as e:
        print(f"Error assessing quantum: {str(e)}")
        return {
            "cost_estimate": 0.0,
            "time_impact_days": 0,
            "calculation_method": "Error assessing quantum. Please try again."
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
    
    try:
        prompt = f"""
        Based on owner's correspondence and project logs, list possible counterclaims and defenses.
        
        Focus on:
        1. Concurrent delay
        2. Improper notice
        3. Failure to mitigate
        4. Other potential defenses
        
        Provide a well-structured, professional analysis of approximately 800 words, organized by counterclaim type.
        
        Project Records:
        {record_text}
        """
        
        response = openai.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3
        )
        
        return response.choices[0].message.content
        
    except Exception as e:
        print(f"Error evaluating counterclaims: {str(e)}")
        return "Error evaluating counterclaims. Please try again."

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
        
        response = openai.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3
        )
        
        return response.choices[0].message.content
        
    except Exception as e:
        print(f"Error suggesting dispute strategy: {str(e)}")
        return "Error suggesting dispute strategy. Please try again."

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
        if len(context) > 10000:
            context = context[:10000] + "...[truncated due to length]"
            
        prompt = f"""
        You are an AI assistant for a construction claims management system. Answer the user's question 
        based only on the provided project document context. If you cannot find the answer in the 
        provided context, clearly state that you don't have enough information to answer accurately.
        
        Project Document Context:
        {context}
        
        User Question:
        {user_message}
        """
        
        response = openai.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2
        )
        
        return response.choices[0].message.content
        
    except Exception as e:
        print(f"Error in chatbot: {str(e)}")
        return "I'm sorry, but I encountered an error while processing your request. Please try again."
