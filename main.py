from flask import Flask, request, jsonify
import pandas as pd
import re
import random
import joblib
import os
import requests
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics.pairwise import cosine_similarity
import logging
import sys

# =====================================================
# CONFIG
# =====================================================
API_KEY = "my-secret-api-key"
GUVI_CALLBACK = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
MAX_TURNS = 5
CSV_PATH = "fraud_detection.csv"
MODEL_PATH = "model/scam_model.joblib"

app = Flask(__name__)
SESSION_STORE = {}

# =====================================================
# SETUP CONSOLE LOGGING
# =====================================================
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

# =====================================================
# ROOT ROUTE FOR HEALTH CHECK
# =====================================================
@app.route("/", methods=["GET"])
def index():
    return "Honeypot API is live!", 200

# =====================================================
# TEXT CLEANING
# =====================================================
def clean(text):
    text = str(text).lower()
    text = re.sub(r"http\S+", " URL ", text)
    text = re.sub(r"[^a-z\s]", "", text)
    return text.strip()

# =====================================================
# LOAD OR TRAIN SCAM DETECTOR
# =====================================================
if os.path.exists(MODEL_PATH):
    logging.info("📂 Loading pre-trained scam detector...")
    scam_model = joblib.load(MODEL_PATH)
    logging.info("✅ Model loaded")
else:
    logging.info("📊 Training scam detector...")
    df = pd.read_csv(CSV_PATH)
    df["clean"] = df["text"].astype(str).apply(clean)
    scam_model = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1,2))),
        ("clf", LogisticRegression(max_iter=1000))
    ])
    scam_model.fit(df["clean"], df["is_scam"])
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(scam_model, MODEL_PATH)
    logging.info("✅ Model trained and saved")

# =====================================================
# PREPARE DATASET FOR CLOSEST REPLY
# =====================================================
df = pd.read_csv(CSV_PATH)
df["clean"] = df["text"].astype(str).apply(clean)

scammer_df = df[df["sender"] == "scammer"].reset_index(drop=True)
agent_df = df[df["sender"] == "agent"].reset_index(drop=True)

vectorizer = TfidfVectorizer(ngram_range=(1,2))
scammer_vectors = vectorizer.fit_transform(scammer_df["clean"])
agent_vectors = vectorizer.transform(agent_df["clean"])

logging.info(f"📊 Dataset loaded: total={len(df)}, scammer={len(scammer_df)}, agent={len(agent_df)}")

# =====================================================
# HONEYPOT AI CLASS
# =====================================================
class HoneypotAI:
    def __init__(self):
        self.intel = {}
        self.messages_exchanged = 0

    def extract_intel(self, msg):
        patterns = {
            "upiIds": r"\b[\w.\-]{2,}@[a-zA-Z]{2,}\b",
            "bankAccounts": r"\b\d{9,18}\b",
            "ifscCodes": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
            "phishingLinks": r"https?://\S+",
            "phoneNumbers": r"\+?\d{10,14}",
            "suspiciousKeywords": r"\b(urgent|verify|blocked|suspended|payment)\b"
        }
        for key, pattern in patterns.items():
            found = re.findall(pattern, msg, flags=re.IGNORECASE)
            if found:
                self.intel.setdefault(key, []).extend(found)
                logging.info(f"🕵️ Intel extracted: {key} -> {found}")

    def respond(self, msg, conversation_history=None):
        logging.info(f"💬 Received message: {msg}")
        self.messages_exchanged += 1
        self.extract_intel(msg)

        combined_msg = " ".join([m["text"] for m in (conversation_history or [])] + [msg])
        user_vec = vectorizer.transform([clean(combined_msg)])

        # Similarity with scammer messages
        sims = cosine_similarity(user_vec, scammer_vectors)[0]
        top_k = sims.argsort()[-5:][::-1]
        chosen_idx = random.choice(top_k)
        matched_scam = scammer_df.iloc[chosen_idx]
        conv_id = matched_scam["conversation_id"]
        turn = matched_scam["turn"]

        logging.info(f"🔎 Matched scammer message (conv_id={conv_id}, turn={turn}): {matched_scam['text']}")

        # Next agent reply in the same conversation
        agent_row = df[
            (df["conversation_id"] == conv_id) &
            (df["sender"] == "agent") &
            (df["turn"] > turn)
        ].sort_values("turn").head(1)

        if not agent_row.empty:
            reply_text = agent_row.iloc[0]["text"]
            logging.info(f"🤖 Agent reply (same conversation): {reply_text}")
            return reply_text

        # Closest agent message if no exact next turn
        agent_sims = cosine_similarity(user_vec, agent_vectors)[0]
        top_agent_idx = agent_sims.argsort()[-5:][::-1]
        reply_text = agent_df.iloc[random.choice(top_agent_idx)]["text"]
        logging.info(f"🤖 Agent reply (closest match): {reply_text}")
        return reply_text

# =====================================================
# API AUTHENTICATION
# =====================================================
def authorized(req):
    return req.headers.get("x-api-key") == API_KEY

# =====================================================
# FINAL CALLBACK
# =====================================================
def send_final_callback(session_id):
    session = SESSION_STORE[session_id]
    hp = session["honeypot"]
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": hp.messages_exchanged,
        "extractedIntelligence": hp.intel,
        "agentNotes": "Autonomous agentic honeypot engaged scammer using dataset-based replies"
    }
    try:
        requests.post(GUVI_CALLBACK, json=payload, timeout=5)
        logging.info(f"✅ Final callback sent for session {session_id}")
    except Exception as e:
        logging.error(f"❌ Failed to send final callback: {e}")

# =====================================================
# MAIN API
# =====================================================
@app.route("/honeypot", methods=["POST"])
def honeypot_api():
    if not authorized(request):
        logging.warning("⚠️ Unauthorized access attempt")
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    logging.info(f"📥 Incoming JSON: {data}")
    session_id = data["sessionId"]
    msg = data["message"]["text"]
    conversation_history = data.get("conversationHistory", [])

    if session_id not in SESSION_STORE:
        SESSION_STORE[session_id] = {
            "honeypot": HoneypotAI(),
            "scamDetected": False
        }

    session = SESSION_STORE[session_id]
    hp = session["honeypot"]

    # Scam detection
    if not session["scamDetected"]:
        session["scamDetected"] = bool(scam_model.predict([clean(msg)])[0])
        logging.info(f"🛡️ Scam detection result: {session['scamDetected']}")

    # Generate dataset-based reply
    reply = hp.respond(msg, conversation_history) if session["scamDetected"] else "Okay."
    logging.info(f"💌 Reply sent: {reply}")

    # Final callback if max turns reached
    if session["scamDetected"] and hp.messages_exchanged >= MAX_TURNS:
        send_final_callback(session_id)

    return jsonify({
        "status": "success",
        "reply": reply,
        "collectedIntel": hp.intel
    })

# =====================================================
# RUN SERVER (RENDER-READY)
# =====================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))  # Use Render port or fallback
    logging.info(f"🚀 Honeypot API starting on port {port}...")
    app.run(host="0.0.0.0", port=port)
