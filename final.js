import express from "express";
import axios from "axios";

const app = express();
app.use(express.json());

// ==============================
// CONFIG
// ==============================
const API_KEY = "my-secret-api-key";
const GUVI_CALLBACK = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult";
const MAX_TURNS = 6;

// ==============================
// SESSION STORE (in-memory)
// ==============================
const SESSIONS = {};

// ==============================
// UTIL
// ==============================
function authorized(req) {
  return req.headers["x-api-key"] === API_KEY;
}

function log(msg) {
  console.log(new Date().toISOString(), msg);
}

// ==============================
// INTENT DETECTION
// ==============================
function detectIntent(text) {
  const t = text.toLowerCase();
  if (t.includes("blocked") || t.includes("suspend")) return "ACCOUNT_BLOCK";
  if (t.includes("upi") || t.includes("payment")) return "PAYMENT_REQUEST";
  if (t.includes("otp") || t.includes("code")) return "OTP_REQUEST";
  if (t.includes("link") || t.includes("verify")) return "PHISHING_LINK";
  return "GENERIC";
}

// ==============================
// REALISTIC REPLY BANK
// ==============================
const REPLIES = {
  ACCOUNT_BLOCK: [
    "Why is my account being blocked?",
    "I don’t understand, what caused the suspension?",
    "This is sudden, can you explain the issue?",
    "Which transaction are you referring to?",
    "I haven’t received any notice before this"
  ],
  PAYMENT_REQUEST: [
    "Why do you need my UPI ID?",
    "Is there any other way to fix this?",
    "I’m not comfortable sharing payment details",
    "Can this be resolved without sending money?",
    "I usually visit the bank for such matters"
  ],
  OTP_REQUEST: [
    "Why would you need my OTP?",
    "OTP is confidential, isn’t it?",
    "I haven’t received any OTP yet",
    "Are you sure this is required?",
    "Can you resend it first?"
  ],
  PHISHING_LINK: [
    "That link is not opening for me",
    "Is there an official website instead?",
    "Can I verify this at my branch?",
    "I don’t usually click links like this",
    "Do you have a reference number?"
  ],
  GENERIC: [
    "Can you explain this properly?",
    "I don’t understand what you mean",
    "What should I do now?",
    "Please clarify",
    "Give me more details"
  ]
};

// ==============================
// PICK NON-REPEATING REPLY
// ==============================
function pickReply(intent, used) {
  const options = REPLIES[intent] || REPLIES.GENERIC;
  const available = options.filter(r => !used.includes(r));
  return (available.length ? available : options)
    [Math.floor(Math.random() * (available.length || options.length))];
}

// ==============================
// INTELLIGENCE EXTRACTION
// ==============================
function extractIntel(text, intel) {
  const rules = {
    upiIds: /\b[\w.\-]{2,}@[a-zA-Z]{2,}\b/g,
    bankAccounts: /\b\d{9,18}\b/g,
    phishingLinks: /https?:\/\/\S+/g,
    phoneNumbers: /\+?\d{10,14}/g,
    suspiciousKeywords: /\b(urgent|verify|blocked|suspended|payment)\b/gi
  };

  for (const k in rules) {
    const found = text.match(rules[k]);
    if (found) {
      intel[k] = intel[k] || [];
      intel[k].push(...found);
    }
  }
}

// ==============================
// HEALTH CHECK
// ==============================
app.get("/", (req, res) => {
  res.send("Honeypot API is live");
});

// ==============================
// MAIN HONEYPOT API
// ==============================
app.post("/honeypot", async (req, res) => {
  if (!authorized(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const { sessionId, message, conversationHistory = [] } = req.body;
  const text = message.text;

  log(`Incoming message [${sessionId}]: ${text}`);

  if (!SESSIONS[sessionId]) {
    SESSIONS[sessionId] = {
      messages: 0,
      usedReplies: [],
      intel: {},
      scamDetected: false
    };
  }

  const session = SESSIONS[sessionId];
  session.messages++;

  // Simple scam detection
  const intent = detectIntent(text);
  if (intent !== "GENERIC") session.scamDetected = true;

  // Extract intelligence
  extractIntel(text, session.intel);

  // Generate reply
  const replyBase = pickReply(intent, session.usedReplies);
  session.usedReplies.push(replyBase);

  const reply = replyBase;

  // Final callback
  if (session.scamDetected && session.messages >= MAX_TURNS) {
    try {
      await axios.post(GUVI_CALLBACK, {
        sessionId,
        scamDetected: true,
        totalMessagesExchanged: session.messages,
        extractedIntelligence: session.intel,
        agentNotes: "Scammer used urgency, payment pressure and verification tactics"
      }, { timeout: 5000 });

      log(`Final callback sent for ${sessionId}`);
    } catch (e) {
      log(`Callback failed: ${e.message}`);
    }
  }

  // 🔴 STRICT GUVI RESPONSE FORMAT
  res.json({
    status: "success",
    reply
  });
});

// ==============================
// RUN (RENDER READY)
// ==============================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  log(`Honeypot running on port ${PORT}`);
});
