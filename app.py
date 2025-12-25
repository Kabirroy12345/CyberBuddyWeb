from flask import Flask, request, jsonify, send_from_directory
import sqlite3
import time
import re
import math
import hashlib
from google import genai
import requests
import os

app = Flask(__name__, static_folder='.')

# Initialize SQLite Database
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    
    # Reported links table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reported_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            link TEXT,
            timestamp TEXT,
            username TEXT,
            ip_address TEXT,
            threat_type TEXT DEFAULT 'unknown'
        )
    """)
    
    # Scan history table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            result TEXT,
            risk_score INTEGER,
            timestamp TEXT,
            analysis TEXT
        )
    """)
    
    # Password checks table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash TEXT,
            strength_score INTEGER,
            timestamp TEXT
        )
    """)
    
    conn.commit()
    conn.close()

init_db()

# Configure API keys
GEMINI_API_KEY = "AIzaSyDNPoZp_SgiK5nu-OAaNENxAuctqdrecMY"
client = genai.Client(api_key=GEMINI_API_KEY)

# Cybersecurity Expert System Prompt
CYBER_SYSTEM_PROMPT = """You are CyberGuard AI, an expert cybersecurity assistant. You specialize in:
- Threat detection and analysis
- Phishing and malware identification
- Password security best practices
- Network security guidance
- Privacy protection tips
- Incident response procedures

Always provide actionable, security-focused advice. Use emojis to make responses engaging.
Keep responses concise but informative. Warn users about potential risks."""

# Common weak passwords list
WEAK_PASSWORDS = [
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'master',
    'dragon', '111111', 'baseball', 'iloveyou', 'trustno1', 'sunshine', 'princess',
    'admin', 'welcome', 'shadow', 'ashley', 'football', 'jesus', 'michael',
    'ninja', 'mustang', 'password1', 'password123', 'letmein', 'login'
]

# Serve static files
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/app.js')
def serve_js():
    return send_from_directory('.', 'app.js')

@app.route('/styles.css')
def serve_css():
    return send_from_directory('.', 'styles.css')

# Enhanced Chat with Cybersecurity Focus
@app.route("/chat", methods=["POST"])
def chat():
    user_message = request.json.get("message")
    if not user_message:
        return jsonify({"response": "Please enter a message."})

    try:
        full_prompt = f"{CYBER_SYSTEM_PROMPT}\n\nUser: {user_message}\n\nCyberGuard AI:"
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=full_prompt
        )
        bot_response = response.text.strip()
    except Exception as e:
        print("Error:", e)
        bot_response = f"⚠️ Error: {str(e)}"

    return jsonify({"response": bot_response})

# AI-Powered URL Analysis (Replaces Google Safe Browsing)
@app.route("/verify", methods=["POST"])
def verify():
    link = request.json.get("link")
    if not link:
        return jsonify({"message": "No link provided for verification.", "risk_score": 0})

    try:
        # AI-powered threat analysis
        analysis_prompt = f"""Analyze this URL for cybersecurity threats: {link}

Evaluate the following:
1. Domain reputation (suspicious TLD, newly registered, typosquatting)
2. URL structure (excessive subdomains, suspicious parameters, encoded characters)
3. Phishing indicators (mimicking popular sites, urgency keywords)
4. Malware risk (suspicious file extensions, known malware domains)
5. SSL/HTTPS status

Provide a response in this exact format:
RISK_SCORE: [0-100]
STATUS: [SAFE/WARNING/DANGER]
THREATS: [List any detected threats, or "None detected"]
RECOMMENDATION: [Brief security advice]

Be conservative - if uncertain, mark as WARNING."""

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=analysis_prompt
        )
        analysis = response.text.strip()
        
        # Parse the response
        risk_score = 0
        status = "SAFE"
        
        if "RISK_SCORE:" in analysis:
            try:
                score_line = [l for l in analysis.split('\n') if 'RISK_SCORE:' in l][0]
                risk_score = int(re.search(r'\d+', score_line).group())
            except:
                risk_score = 50
        
        if "STATUS:" in analysis:
            if "DANGER" in analysis:
                status = "DANGER"
            elif "WARNING" in analysis:
                status = "WARNING"
        
        # Save to history
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scan_history (url, result, risk_score, timestamp, analysis) VALUES (?, ?, ?, ?, ?)",
            (link, status, risk_score, time.strftime("%Y-%m-%d %H:%M:%S"), analysis)
        )
        conn.commit()
        conn.close()
        
        # Format response
        if status == "DANGER":
            emoji = "🚨"
            message = f"DANGER! High-risk URL detected!"
        elif status == "WARNING":
            emoji = "⚠️"
            message = f"Warning: This URL has some suspicious characteristics."
        else:
            emoji = "✅"
            message = f"This URL appears to be safe."
        
        return jsonify({
            "message": f"{emoji} {message}",
            "risk_score": risk_score,
            "status": status,
            "analysis": analysis
        })
        
    except Exception as e:
        print("Verify Error:", e)
        return jsonify({
            "message": f"⚠️ Error analyzing URL: {str(e)}",
            "risk_score": 50,
            "status": "ERROR"
        })

# Report Suspicious Link
@app.route("/report", methods=["POST"])
def report():
    link = request.json.get("link")
    username = request.json.get("username")
    threat_type = request.json.get("threat_type", "unknown")
    ip_address = request.remote_addr
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    if not link:
        return jsonify({"message": "No link provided to report."})

    if not username:
        return jsonify({"message": "Please provide your username before reporting a link."})
    
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO reported_links (link, timestamp, username, ip_address, threat_type) VALUES (?, ?, ?, ?, ?)",
        (link, timestamp, username, ip_address, threat_type)
    )
    conn.commit()
    conn.close()
    
    return jsonify({"message": f"🚨 Suspicious link reported successfully by {username}! Thank you for helping keep the community safe."})

# Password Strength Analyzer
@app.route("/analyze-password", methods=["POST"])
def analyze_password():
    password = request.json.get("password")
    if not password:
        return jsonify({"message": "No password provided.", "score": 0})
    
    # Calculate password strength
    score = 0
    feedback = []
    
    # Length check
    length = len(password)
    if length >= 8:
        score += 20
    if length >= 12:
        score += 10
    if length >= 16:
        score += 10
    if length < 8:
        feedback.append("❌ Password is too short (min 8 characters)")
    
    # Character variety
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    if has_lower:
        score += 10
    else:
        feedback.append("❌ Add lowercase letters")
    
    if has_upper:
        score += 10
    else:
        feedback.append("❌ Add uppercase letters")
    
    if has_digit:
        score += 10
    else:
        feedback.append("❌ Add numbers")
    
    if has_special:
        score += 20
    else:
        feedback.append("❌ Add special characters (!@#$%^&*)")
    
    # Common password check
    if password.lower() in WEAK_PASSWORDS:
        score = min(score, 10)
        feedback.insert(0, "🚨 This is a commonly used password!")
    
    # Entropy calculation
    charset_size = 0
    if has_lower: charset_size += 26
    if has_upper: charset_size += 26
    if has_digit: charset_size += 10
    if has_special: charset_size += 32
    
    if charset_size > 0:
        entropy = length * math.log2(charset_size)
        if entropy >= 60:
            score += 10
    
    # Cap score at 100
    score = min(score, 100)
    
    # Determine strength level
    if score >= 80:
        strength = "STRONG"
        emoji = "🛡️"
        message = "Excellent! Your password is very strong."
    elif score >= 60:
        strength = "GOOD"
        emoji = "✅"
        message = "Good password, but could be stronger."
    elif score >= 40:
        strength = "MODERATE"
        emoji = "⚠️"
        message = "Moderate password. Consider improving it."
    else:
        strength = "WEAK"
        emoji = "🚨"
        message = "Weak password! Please use a stronger one."
    
    # Save anonymized check
    password_hash = hashlib.sha256(password.encode()).hexdigest()[:16]
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO password_checks (password_hash, strength_score, timestamp) VALUES (?, ?, ?)",
        (password_hash, score, time.strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()
    
    return jsonify({
        "message": f"{emoji} {message}",
        "score": score,
        "strength": strength,
        "feedback": feedback,
        "entropy": round(entropy, 2) if charset_size > 0 else 0
    })

# Get Statistics
@app.route("/stats", methods=["GET"])
def get_stats():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    
    # Get total scans
    cursor.execute("SELECT COUNT(*) FROM scan_history")
    total_scans = cursor.fetchone()[0]
    
    # Get threat counts
    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE result = 'DANGER'")
    danger_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE result = 'WARNING'")
    warning_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE result = 'SAFE'")
    safe_count = cursor.fetchone()[0]
    
    # Get reported links count
    cursor.execute("SELECT COUNT(*) FROM reported_links")
    reported_count = cursor.fetchone()[0]
    
    # Get password checks
    cursor.execute("SELECT COUNT(*) FROM password_checks")
    password_checks = cursor.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        "total_scans": total_scans,
        "threats_detected": danger_count,
        "warnings": warning_count,
        "safe_urls": safe_count,
        "reported_links": reported_count,
        "password_checks": password_checks
    })

# Get Recent Scans
@app.route("/history", methods=["GET"])
def get_history():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT url, result, risk_score, timestamp FROM scan_history ORDER BY id DESC LIMIT 10"
    )
    rows = cursor.fetchall()
    conn.close()
    
    history = []
    for row in rows:
        history.append({
            "url": row[0],
            "result": row[1],
            "risk_score": row[2],
            "timestamp": row[3]
        })
    
    return jsonify({"history": history})

if __name__ == "__main__":
    app.run(debug=True)