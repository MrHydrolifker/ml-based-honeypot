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
// SESSION STORE
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

function rand(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// ==============================
// INTENT DETECTION
// ==============================
function detectIntent(text) {
  const t = text.toLowerCase();
  if (t.includes("blocked") || t.includes("suspend")) return "ACCOUNT_BLOCK";
  if (t.includes("upi") || t.includes("payment") || t.includes("transfer"))
    return "PAYMENT_REQUEST";
  if (t.includes("otp") || t.includes("code"))
    return "OTP_REQUEST";
  if (t.includes("link") || t.includes("verify"))
    return "PHISHING_LINK";
  return "GENERIC";
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
// PHASE-AWARE REPLY ENGINE
// ==============================
function generateReply(intent, text, phase, used) {
  const t = text.toLowerCase();

  // ---------- OTP CASES ----------
  if (intent === "OTP_REQUEST") {
    if (t.includes("haven’t received") || t.includes("not received")) {
      return rand([
        "I haven't received any OTP yet, should I wait?",
        "Nothing has come on my phone till now",
        "OTP usually comes late on my number"
      ]);
    }

    if (phase === 1)
      return rand([
        "Why would you need my OTP?",
        "OTP is confidential, right?"
      ]);

    if (phase === 2)
      return rand([
        "I’m a bit worried sharing OTP",
        "I usually don’t give OTP to anyone"
      ]);

    if (phase === 3)
      return rand([
        "If OTP comes, what exactly should I do?",
        "Should I read it or type it somewhere?"
      ]);

    if (phase === 4)
      return rand([
        "Okay wait, I think a message just came",
        "I’m checking my phone now"
      ]);

    return "I’m not sure if I should share this OTP";
  }

  // ---------- PAYMENT CASES ----------
  if (intent === "PAYMENT_REQUEST") {
    if (phase === 1)
      return rand([
        "Why do you need my UPI ID?",
        "I’ve never done this before"
      ]);

    if (phase === 2)
      return rand([
        "Can this be resolved without payment?",
        "Is there any other verification?"
      ]);

    if (phase === 3)
      return rand([
        "I usually go to the bank for such things",
        "Are you sure this is the only way?"
      ]);

    if (phase === 4)
      return rand([
        "My UPI is linked but I don’t use it much",
        "If I do this, will the issue be fixed?"
      ]);

    return "I’m still not comfortable sending money";
  }

  // ---------- ACCOUNT BLOCK ----------
  if (intent === "ACCOUNT_BLOCK") {
    if (phase === 1)
      return rand([
        "Why is my account being blocked?",
        "This is sudden, what happened?"
      ]);

    if (phase === 2)
      return rand([
        "I didn’t receive any message from the bank",
        "Which transaction caused this?"
      ]);

    if (phase === 3)
      return rand([
        "I’m really worried, my salary comes in this account",
        "Can this be stopped somehow?"
      ]);

    if (phase === 4)
      return rand([
        "If I cooperate, will my account remain active?",
        "Please guide me properly"
      ]);

    return "I don’t want my account to get blocked";
  }

  // ---------- PHISHING LINK ----------
  if (intent === "PHISHING_LINK") {
    if (t.includes("not opening")) {
      return rand([
        "That link is not opening for me",
        "The page isn’t loading on my phone"
      ]);
    }

    if (phase === 1)
      return rand([
        "I don’t usually click links like this",
        "Is there an official website?"
      ]);

    if (phase === 2)
      return rand([
        "Can I verify this at the bank branch?",
        "Do you have a reference number?"
      ]);

    if (phase === 3)
      return rand([
        "If I open it, will it fix the issue?",
        "I’m not very good with these links"
      ]);

    return "I’m scared clicking unknown links";
  }

  // ---------- GENERIC ----------
  return rand([
    "Can you explain this properly?",
    "I don’t understand what you mean",
    "What should I do now?",
    "Please clarify",
    "Give me more details"
  ]);
}

// ==============================
// HEALTH CHECK
// ==============================
app.get("/", (req, res) => {
  res.send("Honeypot API is live");
});

// ==============================
// MAIN API
// ==============================
app.post("/honeypot", async (req, res) => {
  if (!authorized(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const { sessionId, message } = req.body;
  const text = message.text;

  log(`Incoming [${sessionId}]: ${text}`);

  if (!SESSIONS[sessionId]) {
    SESSIONS[sessionId] = {
      messages: 0,
      intel: {},
      scamDetected: false
    };
  }

  const session = SESSIONS[sessionId];
  session.messages++;

  const phase = Math.min(session.messages, 5);
  const intent = detectIntent(text);

  if (intent !== "GENERIC") session.scamDetected = true;

  extractIntel(text, session.intel);

  const reply = generateReply(intent, text, phase);

  // FINAL CALLBACK
  if (session.scamDetected && session.messages >= MAX_TURNS) {
    try {
      await axios.post(GUVI_CALLBACK, {
        sessionId,
        scamDetected: true,
        totalMessagesExchanged: session.messages,
        extractedIntelligence: session.intel,
        agentNotes:
          "Scammer used urgency, OTP requests, payment pressure and phishing tactics"
      }, { timeout: 5000 });

      log(`Final callback sent for ${sessionId}`);
    } catch (e) {
      log(`Callback failed: ${e.message}`);
    }
  }

  // 🔴 STRICT RESPONSE FORMAT
  res.json({
    status: "success",
    reply
  });
});

// ==============================
// RUN
// ==============================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  log(`Honeypot running on port ${PORT}`);
});
