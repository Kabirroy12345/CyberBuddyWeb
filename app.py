from flask import Flask, request, jsonify, send_from_directory
import sqlite3
import time
from google import genai
import requests
import os

app = Flask(__name__, static_folder='.')

# Initialize SQLite Database
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reported_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            link TEXT,
            timestamp TEXT,
            username TEXT,
            ip_address TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# Configure API keys
GEMINI_API_KEY = "AIzaSyDNPoZp_SgiK5nu-OAaNENxAuctqdrecMY"
client = genai.Client(api_key=GEMINI_API_KEY)
GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyC4B4MF7856AiE25w4TE9usHqzuYN0_r2k"

# Serve static files
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/app.js')
def serve_js():
    return send_from_directory('.', 'app.js')

@app.route("/chat", methods=["POST"])
def chat():
    user_message = request.json.get("message")
    if not user_message:
        return jsonify({"response": "Please enter a message."})

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=user_message
        )
        bot_response = response.text.strip()
    except Exception as e:
        print("Error:", e)
        bot_response = f"⚠️ Error: {str(e)}"

    return jsonify({"response": bot_response})

@app.route("/verify", methods=["POST"])
def verify():
    link = request.json.get("link")
    if not link:
        return jsonify({"message": "No link provided for verification."})

    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    
    payload = {
        "client": {
            "clientId": "cyberguard-web",
            "clientVersion": "2.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": link}]
        }
    }

    try:
        response = requests.post(url, json=payload)
        data = response.json()
        
        if "matches" in data:
            return jsonify({"message": "🚨 Warning! This link is unsafe and flagged by Google Safe Browsing."})
        else:
            return jsonify({"message": "✅ This link appears to be safe."})
    except Exception as e:
        return jsonify({"message": f"⚠️ Error: Unable to verify the link. {str(e)}"})

@app.route("/report", methods=["POST"])
def report():
    link = request.json.get("link")
    username = request.json.get("username")
    ip_address = request.remote_addr
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    if not link:
        return jsonify({"message": "No link provided to report."})

    if not username:
        return jsonify({"message": "Please provide your username before reporting a link."})
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO reported_links (link, timestamp, username, ip_address) VALUES (?, ?, ?, ?)",
                   (link, timestamp, username, ip_address))
    conn.commit()
    conn.close()
    
    return jsonify({"message": f"🚨 Suspicious link reported successfully by {username}!"})

if __name__ == "__main__":
    app.run(debug=True)