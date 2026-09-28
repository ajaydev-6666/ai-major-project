from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from dotenv import load_dotenv
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import sqlite3, re, os, uuid
from pathlib import Path
from urllib.parse import urlparse
from functools import wraps

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-secret-in-production")
BASE_DIR = Path(__file__).resolve().parent
DB = str(BASE_DIR / "scamshield.db")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "ScamShield@123")

# Demo training set. Replace/extend with a real labeled dataset for evaluation.
TRAINING_DATA = [
    # Scam examples (label=1)
    ("Congratulations you won a lottery claim your prize now", 1),
    ("Your bank account will be blocked verify your OTP immediately", 1),
    ("Urgent payment required click this link to avoid account suspension", 1),
    ("You have received a reward submit your card details to receive it", 1),
    ("Your UPI account needs verification send OTP to continue", 1),
    ("Exclusive investment opportunity guaranteed 40 percent returns send money", 1),
    ("Your parcel is on hold pay a small fee using this link", 1),
    ("Job selected pay registration fee to confirm your offer", 1),
    ("Your account security alert login at the link and verify password", 1),
    ("Win a free smartphone click now and provide your details", 1),
    ("Please transfer money urgently I am stuck and need help", 1),
    ("Claim cashback by entering your bank and card information", 1),
    ("KYC expired update immediately or your account will be closed", 1),
    ("You are selected for a work from home job pay processing charges", 1),
    ("Limited time offer buy now with your card details", 1),
    # Legitimate examples (label=0)
    ("Meeting is scheduled for tomorrow at 10 am", 0),
    ("Your electricity bill for September is available in the official app", 0),
    ("Please find the assignment attached for review", 0),
    ("Your order has been delivered successfully", 0),
    ("Reminder: your appointment is confirmed for Monday", 0),
    ("The project meeting has moved to 3 pm", 0),
    ("Thanks for your payment. Your receipt is available in the app", 0),
    ("Your monthly statement is ready to view in online banking", 0),
    ("Please call me when you are free", 0),
    ("The college has published the examination timetable", 0),
    ("Your train ticket has been booked successfully and your receipt is available.", 0),
    ("The library has extended its opening hours during exam week.", 0),
]

TRAIN_TEXTS = [text for text, label in TRAINING_DATA]
TRAIN_LABELS = [label for text, label in TRAINING_DATA]
if not TRAIN_TEXTS or len(TRAIN_TEXTS) != len(TRAIN_LABELS):
    raise ValueError(f"Training data mismatch: {len(TRAIN_TEXTS)} texts but {len(TRAIN_LABELS)} labels.")
if len(set(TRAIN_LABELS)) < 2:
    raise ValueError("Training data must contain at least two classes.")

vectorizer = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)
X = vectorizer.fit_transform(TRAIN_TEXTS)
model = LogisticRegression(max_iter=1000, class_weight="balanced")
model.fit(X, TRAIN_LABELS)

SCAM_CATEGORIES = {
    "phishing": ["verify", "login", "password", "account", "security", "kyc", "suspension"],
    "banking/upi": ["otp", "upi", "bank", "card", "payment", "transfer"],
    "job": ["job", "work from home", "registration fee", "processing charges"],
    "investment": ["investment", "returns", "guaranteed", "profit"],
    "lottery/reward": ["lottery", "won", "prize", "reward", "cashback", "free"],
    "shopping/delivery": ["parcel", "order", "delivery", "shopping", "offer"],
}

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    con.execute("""CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        input_type TEXT, input_text TEXT, risk REAL,
        category TEXT, reasons TEXT, user_id TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    cols = [r[1] for r in con.execute("PRAGMA table_info(scans)").fetchall()]
    if "user_id" not in cols:
        con.execute("ALTER TABLE scans ADD COLUMN user_id TEXT")
    con.execute("""CREATE TABLE IF NOT EXISTS feedback(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        ai_label TEXT NOT NULL,
        user_label TEXT NOT NULL,
        confidence TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    )""")
    con.commit()
    con.close()

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Admin login required"}), 401
            return redirect(url_for("admin_login"))
        return fn(*args, **kwargs)
    return wrapper

def category_for(text):
    low = text.lower()
    scores = {k: sum(1 for w in words if w in low) for k, words in SCAM_CATEGORIES.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] else "general scam"

def text_scan(text):
    text = (text or "").strip()
    if not text:
        return {"risk": 0, "category": "unknown", "reasons": ["Enter a message to analyze."]}
    p = float(model.predict_proba(vectorizer.transform([text]))[0][1])
    low = text.lower()
    reasons = []
    patterns = [
        (r"\burgent|immediately|now\b", "Urgency or pressure language"),
        (r"\botp\b", "Requests or mentions an OTP"),
        (r"\b(password|pin|cvv|card details)\b", "Requests sensitive credentials"),
        (r"\b(click|verify|login|update|confirm)\b", "Action/verification language"),
        (r"\b(prize|lottery|reward|cashback|won|free)\b", "Prize/reward bait"),
        (r"\b(pay|payment|transfer|fee|charges)\b", "Payment or fee pressure"),
        (r"\bguaranteed\b|\b\d+\s*%\b", "Unusually attractive financial claim"),
    ]
    for pat, reason in patterns:
        if re.search(pat, low):
            reasons.append(reason)
    rule_bonus = min(len(reasons) * 0.07, 0.28)
    risk = min(0.99, max(0.01, p * 0.82 + rule_bonus))
    label = "Low Risk" if risk < 0.35 else ("Suspicious" if risk < 0.65 else "High Risk")
    if not reasons:
        reasons.append("No strong rule-based scam indicators were detected.")
    return {"risk": round(risk * 100, 1), "category": category_for(text), "label": label, "reasons": reasons[:4]}

def url_scan(url):
    url = (url or "").strip()
    if not url:
        return {"risk": 0, "category": "unknown", "reasons": ["Enter a URL to analyze."]}
    candidate = url if re.match(r"^https?://", url, re.I) else "http://" + url
    p = urlparse(candidate)
    host = p.netloc.lower().split("@")[-1].split(":")[0]
    path = (p.path + "?" + p.query).lower()
    reasons = []
    if p.scheme != "https": reasons.append("URL does not use HTTPS")
    if "@" in url: reasons.append("URL contains @, which can obscure the real destination")
    if len(url) > 90: reasons.append("Unusually long URL")
    if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", host): reasons.append("Uses an IP address instead of a normal domain")
    if any(x in host for x in ["login", "verify", "secure", "update", "account", "bank"]): reasons.append("Domain contains sensitive-action keywords")
    if host.count("-") >= 2: reasons.append("Domain contains multiple hyphens")
    if re.search(r"(login|verify|otp|password|payment|wallet|bank|free|prize)", path): reasons.append("Path contains scam/phishing-related keywords")
    risk = min(0.98, 0.12 + len(reasons) * 0.13 + (0.10 if len(host) > 35 else 0))
    if not reasons: reasons.append("No obvious URL red flags detected by the demo rules.")
    return {"risk": round(risk * 100, 1), "category": "phishing / malicious URL" if risk >= .5 else "URL risk", "label": "Low Risk" if risk < .35 else ("Suspicious" if risk < .65 else "High Risk"), "reasons": reasons[:5], "domain": host}

def get_user_id():
    if not session.get("user_id"):
        session["user_id"] = uuid.uuid4().hex
    return session["user_id"]

def save_scan(kind, raw, result):
    user_id = get_user_id()
    con = db()
    cur = con.execute("INSERT INTO scans(input_type,input_text,risk,category,reasons,user_id) VALUES(?,?,?,?,?,?)", (kind, raw, result["risk"], result["category"], " | ".join(result["reasons"]), user_id))
    scan_id = cur.lastrowid
    con.commit(); con.close()
    return scan_id

@app.route("/")
def index():
    get_user_id()
    return render_template("index.html")

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            return redirect(url_for("admin_dashboard"))
        error = "Invalid admin username or password."
    return render_template("admin_login.html", error=error)

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))

@app.route("/admin")
@admin_required
def admin_dashboard():
    return render_template("admin.html", username=ADMIN_USERNAME)

@app.post("/api/scan/text")
def api_text():
    data = request.get_json(silent=True) or {}
    raw = data.get("text", "")
    result = text_scan(raw)
    if raw.strip(): result["scan_id"] = save_scan("text", raw, result)
    return jsonify(result)

@app.post("/api/scan/url")
def api_url():
    data = request.get_json(silent=True) or {}
    raw = data.get("url", "")
    result = url_scan(raw)
    if raw.strip(): result["scan_id"] = save_scan("url", raw, result)
    return jsonify(result)

@app.get("/api/history")
def history():
    # Normal users see only their own search history; admins see all history.
    con = db()
    if session.get("admin_logged_in"):
        rows = con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 500").fetchall()
    else:
        uid = get_user_id()
        rows = con.execute("SELECT * FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 100", (uid,)).fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])

@app.get("/api/stats")
def stats():
    con = db()
    if session.get("admin_logged_in"):
        total = con.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
        high = con.execute("SELECT COUNT(*) c FROM scans WHERE risk >= 65").fetchone()["c"]
        avg = con.execute("SELECT COALESCE(AVG(risk),0) a FROM scans").fetchone()["a"]
    else:
        uid = get_user_id()
        total = con.execute("SELECT COUNT(*) c FROM scans WHERE user_id=?", (uid,)).fetchone()["c"]
        high = con.execute("SELECT COUNT(*) c FROM scans WHERE user_id=? AND risk >= 65", (uid,)).fetchone()["c"]
        avg = con.execute("SELECT COALESCE(AVG(risk),0) a FROM scans WHERE user_id=?", (uid,)).fetchone()["a"]
    pending = con.execute("SELECT COUNT(*) c FROM feedback WHERE status='pending'").fetchone()["c"] if session.get("admin_logged_in") else 0
    validated = con.execute("SELECT COUNT(*) c FROM feedback WHERE status='validated'").fetchone()["c"] if session.get("admin_logged_in") else 0
    con.close()
    return jsonify({"total": total, "high_risk": high, "avg_risk": round(avg, 1), "pending_feedback": pending, "validated_feedback": validated})

@app.post("/api/feedback")
def api_feedback():
    data = request.get_json(silent=True) or {}
    scan_id, user_label, confidence = data.get("scan_id"), data.get("user_label"), data.get("confidence", "somewhat_sure")
    if not scan_id or user_label not in ("scam", "legitimate") or confidence not in ("very_sure", "somewhat_sure", "not_sure"):
        return jsonify({"error": "Invalid feedback"}), 400
    con = db()
    if session.get("admin_logged_in"):
        scan = con.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    else:
        scan = con.execute("SELECT * FROM scans WHERE id=? AND user_id=?", (scan_id, get_user_id())).fetchone()
    if not scan: con.close(); return jsonify({"error": "Scan not found"}), 404
    ai_label = "scam" if scan["risk"] >= 65 else "legitimate"
    con.execute("INSERT INTO feedback(scan_id,ai_label,user_label,confidence,status) VALUES(?,?,?,?,?)", (scan_id, ai_label, user_label, confidence, "pending"))
    con.commit(); con.close()
    return jsonify({"ok": True, "message": "Feedback stored for admin validation. It will not retrain the model immediately."})

@app.get("/api/feedback")
@admin_required
def feedback():
    con = db(); rows = con.execute("SELECT f.*, s.input_type, s.input_text, s.risk, s.category FROM feedback f JOIN scans s ON s.id=f.scan_id ORDER BY f.id DESC LIMIT 100").fetchall(); con.close()
    return jsonify([dict(r) for r in rows])

@app.post("/api/feedback/validate")
@admin_required
def validate_feedback():
    data = request.get_json(silent=True) or {}; feedback_id, action = data.get("feedback_id"), data.get("action")
    if action not in ("approve", "reject"): return jsonify({"error": "Invalid validation action"}), 400
    con = db(); con.execute("UPDATE feedback SET status=? WHERE id=?", ("validated" if action == "approve" else "rejected", feedback_id)); con.commit(); con.close()
    return jsonify({"ok": True, "status": "validated" if action == "approve" else "rejected"})

init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
