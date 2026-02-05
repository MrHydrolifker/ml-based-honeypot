from flask import Flask, request, jsonify
import pandas as pd
import re, random, os, sys, time, joblib, requests, logging
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics.pairwise import cosine_similarity

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
# LOGGING (SERVER SIDE ONLY)
# =====================================================
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

# =====================================================
# HEALTH CHECK
# =====================================================
@app.route("/", methods=["GET"])
def index():
    return "Honeypot API is live!", 200

# =====================================================
# UTIL
# =====================================================
def clean(text):
    text = str(text).lower()
    text = re.sub(r"http\S+", " URL ", text)
    text = re.sub(r"[^a-z\s]", "", text)
    return text.strip()

def authorized(req):
    return req.headers.get("x-api-key") == API_KEY

# =====================================================
# LOAD MODEL
# =====================================================
if os.path.exists(MODEL_PATH):
    logging.info("✅ Model loaded")
    scam_model = joblib.load(MODEL_PATH)
else:
    logging.info("📊 Training model")
    df_train = pd.read_csv(CSV_PATH)
    df_train["clean"] = df_train["text"].apply(clean)
    scam_model = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1,2))),
        ("clf", LogisticRegression(max_iter=1000))
    ])
    scam_model.fit(df_train["clean"], df_train["is_scam"])
    os.makedirs("model", exist_ok=True)
    joblib.dump(scam_model, MODEL_PATH)

# =====================================================
# DATASET FOR AGENT RESPONSES
# =====================================================
df = pd.read_csv(CSV_PATH)
df["clean"] = df["text"].apply(clean)

scammer_df = df[df["sender"] == "scammer"].reset_index(drop=True)
agent_df = df[df["sender"] == "agent"].reset_index(drop=True)

vectorizer = TfidfVectorizer(ngram_range=(1,2))
scammer_vectors = vectorizer.fit_transform(scammer_df["clean"])
agent_vectors = vectorizer.transform(agent_df["clean"])

logging.info(f"📊 Dataset loaded: {len(df)} rows")

# =====================================================
# HONEYPOT AGENT
# =====================================================
class HoneypotAI:
    def __init__(self):
        self.intel = {}
        self.messages_exchanged = 0

    def extract_intel(self, msg):
        patterns = {
            "upiIds": r"\b[\w.\-]{2,}@[a-zA-Z]{2,}\b",
            "bankAccounts": r"\b\d{9,18}\b",
            "phishingLinks": r"https?://\S+",
            "phoneNumbers": r"\+?\d{10,14}",
            "suspiciousKeywords": r"\b(urgent|verify|blocked|suspended|payment)\b"
        }
        for k, p in patterns.items():
            found = re.findall(p, msg, flags=re.I)
            if found:
                self.intel.setdefault(k, []).extend(found)

    def respond(self, msg, history):
        self.messages_exchanged += 1
        self.extract_intel(msg)

        t0 = time.time()
        combined = " ".join([m["text"] for m in history] + [msg])
        user_vec = vectorizer.transform([clean(combined)])
        logging.info(f"🧮 Vectorization: {time.time() - t0:.3f}s")

        t1 = time.time()
        sims = cosine_similarity(user_vec, scammer_vectors)[0]
        logging.info(f"📐 Similarity: {time.time() - t1:.3f}s")

        idx = random.choice(sims.argsort()[-5:])
        conv_id = scammer_df.iloc[idx]["conversation_id"]
        turn = scammer_df.iloc[idx]["turn"]

        agent_row = df[
            (df["conversation_id"] == conv_id) &
            (df["sender"] == "agent") &
            (df["turn"] > turn)
        ].sort_values("turn").head(1)

        if not agent_row.empty:
            return agent_row.iloc[0]["text"]

        return agent_df.sample(1).iloc[0]["text"]

# =====================================================
# FINAL CALLBACK
# =====================================================
def send_final_callback(session_id):
    s = SESSION_STORE[session_id]
    hp = s["honeypot"]

    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": hp.messages_exchanged,
        "extractedIntelligence": hp.intel,
        "agentNotes": "Scammer used urgency and payment redirection"
    }

    try:
        requests.post(GUVI_CALLBACK, json=payload, timeout=5)
        logging.info("📡 Final callback sent")
    except Exception as e:
        logging.error(f"❌ Callback failed: {e}")

# =====================================================
# MAIN API
# =====================================================
@app.route("/honeypot", methods=["POST"])
def honeypot_api():
    start = time.time()

    if not authorized(request):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    session_id = data["sessionId"]
    msg = data["message"]["text"]
    history = data.get("conversationHistory", [])

    if session_id not in SESSION_STORE:
        SESSION_STORE[session_id] = {
            "honeypot": HoneypotAI(),
            "scamDetected": False
        }

    s = SESSION_STORE[session_id]
    hp = s["honeypot"]

    if not s["scamDetected"]:
        s["scamDetected"] = bool(scam_model.predict([clean(msg)])[0])

    reply = hp.respond(msg, history)

    if s["scamDetected"] and hp.messages_exchanged >= MAX_TURNS:
        send_final_callback(session_id)

    elapsed = time.time() - start
    if elapsed > 30:
        logging.error(f"⛔ Request exceeded 30s: {elapsed:.2f}s")
    elif elapsed > 20:
        logging.warning(f"⚠️ Slow request: {elapsed:.2f}s")
    else:
        logging.info(f"✅ Request done in {elapsed:.2f}s")

    # 🔴 STRICT GUVI RESPONSE FORMAT
    return jsonify({
        "status": "success",
        "reply": reply
    })

# =====================================================
# RUN
# =====================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
