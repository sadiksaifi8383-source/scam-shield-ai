import os, re, json, sqlite3, random, shutil, threading, base64
from datetime import datetime, timezone
from urllib.parse import urlparse, quote, urlencode
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from flask import Flask, jsonify, request, send_file

try:  # local QR decoder (no internet needed): python -m pip install opencv-python-headless
    import cv2
    import numpy as np
except ImportError:
    cv2 = None

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "scam_shield.db")
API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()  # optional; never hardcode keys
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024


# ---------- CORS ----------
@app.after_request
def cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    return resp


@app.before_request
def preflight():
    if request.method == "OPTIONS":
        return ("", 204)


# ---------- database ----------
def run(sql, args=(), fetch=False):
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    try:
        cur = con.execute(sql, args)
        rows = cur.fetchall() if fetch else None
        con.commit()
        return rows if fetch else cur
    finally:
        con.close()


def init_db():
    run("""CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT, scan_type TEXT NOT NULL, subject TEXT,
        risk TEXT NOT NULL, score INTEGER NOT NULL, status TEXT NOT NULL,
        findings TEXT, created_at TEXT NOT NULL)""")
    run("CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT)")
    run("""CREATE TABLE IF NOT EXISTS alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, kind TEXT, fp TEXT,
        provider TEXT, status TEXT NOT NULL, detail TEXT, message TEXT)""")


def save_scan(stype, subject, res):
    cur = run("INSERT INTO scans(scan_type,subject,risk,score,status,findings,created_at) VALUES(?,?,?,?,?,?,?)",
              (stype, subject, res["risk"], res["score"], res["status"], json.dumps(res["findings"]),
               datetime.now(timezone.utc).isoformat(timespec="seconds")))
    return cur.lastrowid


# ---------- analysis helpers ----------
def fail(msg, code, status=400):
    return jsonify({"error": msg, "code": code}), status


def make_result(score, confirmed, findings, extra=None):
    score = max(0, min(100, int(score)))
    if confirmed:
        score, status = max(score, 90), "confirmed_threat"
    else:
        status = "heuristic_warning" if score >= 25 else "no_known_threat"
    res = {"risk": "HIGH" if score >= 60 else "MEDIUM" if score >= 25 else "LOW",
           "score": score, "status": status, "findings": findings}
    res.update(extra or {})
    return res


URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.I)
BRANDS = ["paypal", "amazon", "microsoft", "google", "apple", "netflix", "sbi", "hdfc", "icici", "axis", "paytm", "flipkart", "phonepe"]
SHORT = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly"}
BAD_TLD = (".xyz", ".top", ".click", ".zip", ".mov", ".icu", ".buzz", ".rest", ".cfd", ".sbs", ".tk", ".ml", ".gq", ".cf")
KEYS = ["login", "verify", "secure", "update", "account", "kyc", "wallet", "bonus", "claim", "refund", "reward", "free"]


def normalize_url(raw):
    u = (raw or "").strip()
    if not u or len(u) > 2048 or re.search(r"\s", u):
        return None
    if not re.match(r"^[a-z][a-z0-9+.-]*://", u, re.I):
        u = "https://" + u
    try:
        p = urlparse(u)
        host = p.hostname
    except ValueError:
        return None
    if p.scheme.lower() not in ("http", "https") or not host or "." not in host:
        return None
    return u


def url_heuristics(url):
    p = urlparse(url)
    host = p.hostname.lower()
    pts, out = 0, []

    def add(n, code, d=""):
        nonlocal pts
        pts += n
        out.append({"c": code, "d": d})

    if p.scheme == "http": add(10, "u_http")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host): add(30, "u_ip")
    if "@" in (p.netloc or ""): add(25, "u_at")
    if "xn--" in host: add(20, "u_puny")
    if host in SHORT: add(15, "u_short")
    if host.endswith(BAD_TLD): add(15, "u_tld")
    if host.count(".") >= 4: add(10, "u_sub")
    if len(url) > 75: add(10, "u_long")
    hits = [k for k in KEYS if k in (host + p.path).lower()]
    if hits: add(min(25, 10 * len(hits)), "u_kw", ", ".join(hits))
    for b in BRANDS:
        if b in host and "-" in host:
            add(20, "u_brand", b)
            break
    return pts, out


def safe_browsing(urls):
    """Returns (matched_urls, note_code). Uses only the standard library."""
    if not API_KEY:
        return set(), "sb_off"
    body = json.dumps({
        "client": {"clientId": "scam-shield-ai", "clientVersion": "1.0"},
        "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                       "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                       "threatEntries": [{"url": u} for u in urls[:20]]}}).encode()
    try:
        req = Request("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + API_KEY, data=body,
                      headers={"Content-Type": "application/json"})
        with urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
        return {m["threat"]["url"] for m in data.get("matches", [])}, None
    except Exception:
        return set(), "sb_err"


def scan_url(url):
    pts, found = url_heuristics(url)

    # Safe local testing only: explicit test marker
    if "scamshield-test-high-risk.invalid" in url.lower():
        return make_result(90, False, [{"c": "test_high_risk", "d": "Local test case only"}], {"test_mode": True})

    matched, note = safe_browsing([url])
    if matched:
        return make_result(pts + 60, True, [{"c": "sb_hit", "d": ""}] + found)
    found = found or [{"c": "none", "d": ""}]
    found.append({"c": note or "sb_clean", "d": ""})
    return make_result(pts, False, found)


F = re.I | re.S
RULES = [
    ("otp", 40, r"\b(otp|cvv|pin|password|passcode)\b.{0,40}\b(share|send|tell|enter|provide|confirm|batao|bhejo)|\b(share|send|tell|enter|provide|confirm)\b.{0,40}\b(otp|cvv|pin|password)"),
    ("urgency", 15, r"urgent|immediately|within \d+ ?(hours?|mins?|minutes?)|last chance|expires? (today|soon)|act now|final warning|turant|abhi|jaldi|aaj hi"),
    ("threat", 25, r"(account|card|sim|upi|khata).{0,30}(block|suspend|clos|deactivat|band|freez)|block ho jay|band ho jay|legal action|arrest|digital arrest"),
    ("reward", 25, r"lottery|you (have )?won|winner|prize|cashback|gift card|congratulations|lucky draw|inaam|jeet(a|e)|free (gift|recharge|iphone)"),
    ("payment", 25, r"(pay|send|transfer|deposit|credit|credited|bhej\w*)\b.{0,30}(\u20b9|rs\.?|inr|\$|money|amount|fee|paisa|paise)|processing fee|registration fee|collect request|upi pin"),
    ("trading", 30, r"trade details|profit credited|daily return|investment scheme|crypto bonus|share market tips|demat account"),
    ("kyc", 20, r"\bkyc\b|pan (card )?(update|verify)|aadhaar.{0,20}(link|update|verify)"),
    ("brand", 10, r"\b(sbi|hdfc|icici|axis bank|paytm|phonepe|google ?pay|amazon|flipkart|income tax|rbi|customs|courier|fedex|dhl|india post|trai)\b"),
    ("click", 15, r"click (here|the link|below)|tap (the )?link|verify (now|your)|update (now|your)|login (here|now)"),
    ("remote", 30, r"anydesk|teamviewer|quicksupport|\.apk\b|install (this )?app"),
    ("job", 25, r"work from home.{0,40}(earn|\u20b9|rs)|guaranteed returns?|double your money|part[- ]time job.{0,30}(earn|daily)"),
]
ATTACH = re.compile(r"[\w\-. ]+\.(exe|scr|bat|cmd|js|vbs|jar|apk|iso|zip|rar|html?|docm|xlsm)\b", re.I)


def analyze_text(text, is_email=False):
    pts, found = 0, []
    for code, w, pat in RULES:
        if re.search(pat, text, F):
            pts += w
            found.append({"c": code, "d": ""})
    urls = list(dict.fromkeys(URL_RE.findall(text)))[:10]
    norm = [n for n in (normalize_url(u) for u in urls) if n]
    matched, note = safe_browsing(norm) if norm else (set(), None)
    link_pts = 0
    for n in norm:
        found.append({"c": "link", "d": n})
        p, why = url_heuristics(n)
        if n in matched:
            found.append({"c": "sb_hit", "d": n})
            link_pts += 60
        else:
            # short URLs in SMS/messages get a higher heuristic weight
            if any(sh in n.lower() for sh in SHORT):
                link_pts += 25
            else:
                link_pts += p // 2
        found += [{"c": w["c"], "d": w["d"]} for w in why]
    if norm and note and not matched:
        found.append({"c": note, "d": ""})
    pts += min(link_pts, 70)
    if is_email:
        m = re.search(r"^from:\s*(.*)$", text, re.I | re.M)
        if m:
            line = m.group(1)
            a = re.search(r"[\w.+-]+@([\w.-]+)", line)
            dom = a.group(1).lower() if a else ""
            for b in BRANDS:
                if b in line.lower() and dom and b not in dom:
                    pts += 30
                    found.append({"c": "e_spoof", "d": dom})
                    break
        if ATTACH.search(text):
            pts += 25
            found.append({"c": "e_attach", "d": ""})
        if re.search(r"dear (customer|user|account holder|sir/madam)", text, re.I):
            pts += 10
            found.append({"c": "e_generic", "d": ""})
    if not found:
        found.append({"c": "none", "d": ""})
    return make_result(pts, bool(matched), found, {"links_checked": len(norm)})


def verdict_for(res):
    """Safe only if Google Safe Browsing really ran and found nothing."""
    if res["status"] == "confirmed_threat":
        return "malicious"
    if res["status"] == "heuristic_warning":
        return "suspicious"
    if any(f["c"] == "sb_clean" for f in res["findings"]):
        return "safe"
    return "unverified"


def get_json_field(*names, maxlen=20000):
    d = request.get_json(silent=True) or {}
    for n in names:
        v = d.get(n)
        if isinstance(v, str) and v.strip():
            return v.strip()[:maxlen], d
    return None, d


# ---------- local QR decoding (OpenCV, no internet needed) ----------
def decode_qr_bytes(data):
    """Decode a QR code from image bytes. Returns (text, error_code)."""
    img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        return None, "bad_image"
    h, w = img.shape[:2]
    if max(h, w) > 1600:
        s = 1600.0 / max(h, w)
        img = cv2.resize(img, None, fx=s, fy=s, interpolation=cv2.INTER_AREA)
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    padded = cv2.copyMakeBorder(gray, 60, 60, 60, 60, cv2.BORDER_CONSTANT, value=255)
    variants = [img, gray, padded, 255 - padded,
                cv2.resize(padded, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)]
    det = cv2.QRCodeDetector()
    for v in variants:
        try:
            text, _, _ = det.detectAndDecode(v)
            if text:
                return text, None
            ok, texts, _, _ = det.detectAndDecodeMulti(v)
            if ok:
                for t in texts:
                    if t:
                        return t, None
        except cv2.error:
            pass
    return None, "no_qr"


@app.post("/decode-qr")
def decode_qr():
    data = request.get_data()
    if not data:
        return fail("No image received.", "empty_image")
    if cv2 is None:
        return fail("QR decoder not installed. Run: python -m pip install opencv-python-headless", "no_decoder", 503)
    text, err = decode_qr_bytes(data)
    if err == "bad_image":
        return fail("This file is not a readable image.", "bad_image")
    if not text:
        return fail("No QR code found. Try a clearer image.", "no_qr", 422)
    return jsonify({"text": text[:2100]})


# ---------- Screenshot Inspector: QR code + text (OCR) ----------
QR_LINK = re.compile(r"^(https?://|www\.)\S+$|^[\w-]+(\.[\w-]+)+(/\S*)?$", re.I)


def find_tesseract():
    p = shutil.which("tesseract")
    if p:
        return p
    for c in (r"C:\Program Files\Tesseract-OCR\tesseract.exe",
              r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
              os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Tesseract-OCR", "tesseract.exe")):
        if os.path.isfile(c):
            return c
    return None


def ocr_text(data):
    """Read text from a screenshot with Tesseract. Returns (text, error_code)."""
    try:
        import pytesseract
    except ImportError:
        return None, "ocr_missing"
    exe = find_tesseract()
    if not exe:
        return None, "ocr_no_engine"
    pytesseract.pytesseract.tesseract_cmd = exe
    img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        return None, "bad_image"
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    h, w = gray.shape
    if max(h, w) > 3000:
        sc = 3000.0 / max(h, w)
        gray = cv2.resize(gray, None, fx=sc, fy=sc, interpolation=cv2.INTER_AREA)
    elif w < 900:
        gray = cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
    best = ""
    try:
        for im in (gray, 255 - gray):  # second pass helps dark-mode screenshots
            txt = pytesseract.image_to_string(im, config="--oem 3 --psm 6").strip()
            if len(re.findall(r"\w", txt)) > len(re.findall(r"\w", best)):
                best = txt
    except pytesseract.TesseractNotFoundError:
        return None, "ocr_no_engine"
    except Exception:
        app.logger.exception("OCR failed")
        return None, "ocr_failed"
    return best, None


def merge_results(a, b):
    base, other = (a, b) if a["score"] >= b["score"] else (b, a)
    seen = {(f["c"], f["d"]) for f in base["findings"]}
    findings = [f for f in base["findings"] + other["findings"] if f["c"] != "none"]
    uniq = []
    for f in findings:
        k = (f["c"], f["d"])
        if k not in seen or f in base["findings"]:
            uniq.append(f)
            seen.add(k)
    confirmed = a["status"] == "confirmed_threat" or b["status"] == "confirmed_threat"
    return make_result(max(a["score"], b["score"]), confirmed, uniq or [{"c": "none", "d": ""}],
                       {"links_checked": a.get("links_checked", 0) + 1})


@app.post("/inspect-image")
def inspect_image():
    data = request.get_data()
    if not data:
        return fail("Please upload an image.", "empty_image")
    if cv2 is None:
        return fail("Image tools not installed. Run: python -m pip install opencv-python-headless", "no_decoder", 503)
    qr_text, err = decode_qr_bytes(data)
    if err == "bad_image":
        return fail("This file is not a readable image.", "bad_image")
    qr_res = None
    if qr_text and QR_LINK.match(qr_text.strip()):
        qr_url = normalize_url(qr_text.strip())
        if qr_url:
            qr_res = scan_url(qr_url)
    text, ocr_err = ocr_text(data)
    text_res = analyze_text(text) if text and len(text) >= 5 else None
    if not qr_res and not text_res:
        if ocr_err in ("ocr_missing", "ocr_no_engine"):
            return fail("Text reading (OCR) is not set up.", ocr_err, 503)
        if ocr_err == "ocr_failed":
            return fail("Could not read this image.", "ocr_failed", 500)
        return fail("No readable text or QR code found. Try a clearer image.", "no_content", 422)
    if qr_res and text_res:
        res = merge_results(text_res, qr_res)
    else:
        res = dict(qr_res or text_res)
    subject = "Screenshot (%d characters read, text not stored)" % len(text or "")
    res.update({"scan_type": "screenshot", "subject": subject, "extracted_text": (text or "")[:3000]})
    if qr_res:
        res["verdict"] = verdict_for(res)
    if ocr_err and not text:
        res["ocr"] = ocr_err  # OCR unavailable, but the QR code was still checked
    res["id"] = save_scan("screenshot", subject, res)
    return jsonify(maybe_alert(res, "screenshot", subject))


# ---------- Caretaker alerts (WhatsApp) ----------
DEFAULTS = {"enabled": "0", "consent": "0", "user_name": "", "caretaker_name": "", "caretaker_phone": "",
            "language": "en", "provider": "link", "callmebot_apikey": ""}
PHONE_RE = re.compile(r"^\+\d{8,15}$")
KIND = {"url": ("link", "लिंक"), "qr": ("QR code", "QR कोड"), "sms": ("SMS", "SMS"), "message": ("message", "संदेश"),
        "email": ("email", "ईमेल"), "screenshot": ("screenshot", "स्क्रीनशॉट")}
REASONS = {
    "otp": ("asks for OTP / PIN / password", "OTP / PIN / पासवर्ड माँगा जा रहा है"),
    "urgency": ("creates urgency or time pressure", "जल्दबाज़ी का दबाव बनाया गया है"),
    "threat": ("threatens account blocking or legal action", "खाता बंद करने या कानूनी कार्रवाई की धमकी"),
    "reward": ("fake lottery / prize / reward", "नकली लॉटरी / इनाम"),
    "payment": ("asks for a payment or fee", "पैसे या शुल्क की माँग"),
    "trading": ("investment / trading-profit scam wording", "निवेश / ट्रेडिंग मुनाफ़े की ठगी जैसी भाषा"),
    "kyc": ("fake KYC / PAN / Aadhaar update", "नकली KYC / PAN / आधार अपडेट"),
    "brand": ("pretends to be a bank or government body", "बैंक या सरकारी संस्था होने का दिखावा"),
    "click": ("pushes you to click a link", "लिंक पर क्लिक करने का दबाव"),
    "remote": ("asks to install an app / remote-access tool", "ऐप या रिमोट-एक्सेस टूल इंस्टॉल करने को कहा"),
    "job": ("too-good-to-be-true job / investment offer", "बहुत अच्छा लगने वाला नौकरी / निवेश ऑफ़र"),
    "u_http": ("unsafe HTTP link", "असुरक्षित HTTP लिंक"),
    "u_ip": ("link uses a raw IP address", "लिंक में सीधा IP पता है"),
    "u_at": ("link hides its real destination", "लिंक असली गंतव्य छिपा रहा है"),
    "u_puny": ("look-alike (punycode) domain", "मिलते-जुलते अक्षरों वाला डोमेन"),
    "u_short": ("shortened link hides the destination", "छोटा लिंक असली गंतव्य छिपाता है"),
    "u_tld": ("domain ending often used in scams", "ठगी में आम डोमेन अंत"),
    "u_sub": ("unusually many subdomains", "असामान्य रूप से अधिक सबडोमेन"),
    "u_long": ("very long link", "बहुत लंबा लिंक"),
    "u_kw": ("sensitive words in the link:", "लिंक में संवेदनशील शब्द:"),
    "u_brand": ("fake brand name in the link:", "लिंक में नकली ब्रांड नाम:"),
    "sb_hit": ("Google Safe Browsing lists it as dangerous", "Google Safe Browsing इसे खतरनाक बताता है"),
    "e_spoof": ("fake sender address:", "नकली प्रेषक पता:"),
    "e_attach": ("risky attachment type", "जोखिम भरा अटैचमेंट"),
    "e_generic": ("generic greeting, not your name", "आपके नाम की जगह सामान्य अभिवादन"),
    "test_high_risk": ("local test case", "स्थानीय परीक्षण"),
}


def get_settings():
    s = dict(DEFAULTS)
    for r in run("SELECT k, v FROM settings", fetch=True):
        if r["k"] in s:
            s[r["k"]] = r["v"] or ""
    return s


def twilio_ready():
    return all(os.environ.get(k, "").strip() for k in ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_WHATSAPP_FROM"))


def public_settings(s):
    out = {k: v for k, v in s.items() if k != "callmebot_apikey"}
    out["enabled"] = s["enabled"] == "1"
    out["consent"] = s["consent"] == "1"
    out["callmebot_apikey_set"] = bool(s["callmebot_apikey"])
    out["twilio_configured"] = twilio_ready()
    return out


def defang(u):
    return re.sub(r"^http", "hxxp", u, flags=re.I).replace(".", "[.]")


def reasons_for(res, lang, limit=4):
    out = []
    for f in res["findings"]:
        pair = REASONS.get(f["c"])
        if not pair:
            continue
        txt = pair[1 if lang == "hi" else 0]
        if f["c"] in ("u_kw", "u_brand", "e_spoof") and f.get("d"):
            txt += " " + f["d"]
        if txt not in out:
            out.append(txt)
    return out[:limit] or [("several scam warning signs", "ठगी के कई संकेत")[1 if lang == "hi" else 0]]


def build_alert_message(res, kind, subject, s):
    hi = s["language"] == "hi"
    k = KIND.get(kind, KIND["message"])[1 if hi else 0]
    who = s["user_name"] or ("आपके परिजन" if hi else "your family member")
    reasons = reasons_for(res, s["language"])
    links = []
    if kind in ("url", "qr") and subject:
        links.append(defang(subject))
    for f in res["findings"]:
        if f["c"] == "link" and f.get("d") and defang(f["d"]) not in links:
            links.append(defang(f["d"]))
    if hi:
        lines = ["⚠️ *Scam Shield चेतावनी*",
                 "%s ने एक %s स्कैन किया, जिसमें *उच्च जोखिम* (ठगी की आशंका) मिला। इसे ब्लॉक कर दिया गया है।" % (who, k),
                 "कारण: " + "; ".join(reasons)]
        if links:
            lines.append("लिंक (सुरक्षा के लिए बदला हुआ): " + links[0])
        lines.append("कृपया %s को फ़ोन करें और कहें कि लिंक न खोलें, OTP/PIN न बताएँ।" % who)
    else:
        lines = ["⚠️ *Scam Shield alert*",
                 "%s scanned a %s and it is *HIGH RISK* (likely scam). It was blocked." % (who, k),
                 "Why: " + "; ".join(reasons)]
        if links:
            lines.append("Link (made unclickable): " + links[0])
        lines.append("Please call %s and tell them not to open it or share any OTP/PIN." % who)
    return "\n".join(lines)[:900]


def send_whatsapp(s, text):
    """Send one WhatsApp message with the chosen provider. Returns (status, detail)."""
    phone = s["caretaker_phone"]
    try:
        if s["provider"] == "callmebot":
            q = urlencode({"phone": phone, "text": text, "apikey": s["callmebot_apikey"], "source": "scamshield"})
            req = Request("https://api.callmebot.com/whatsapp.php?" + q, headers={"User-Agent": "scam-shield-ai"})
            with urlopen(req, timeout=12) as r:
                body = re.sub(r"<[^>]+>", " ", r.read(600).decode("utf-8", "ignore"))
                return "sent", "CallMeBot accepted it (HTTP %s). %s" % (r.status, " ".join(body.split())[:80])
        if s["provider"] == "twilio":
            sid, tok = os.environ["TWILIO_ACCOUNT_SID"].strip(), os.environ["TWILIO_AUTH_TOKEN"].strip()
            frm = os.environ["TWILIO_WHATSAPP_FROM"].strip()
            data = urlencode({"From": frm if frm.startswith("whatsapp:") else "whatsapp:" + frm,
                              "To": "whatsapp:" + phone, "Body": text}).encode()
            auth = base64.b64encode(("%s:%s" % (sid, tok)).encode()).decode()
            req = Request("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json" % sid, data=data,
                          headers={"Authorization": "Basic " + auth})
            with urlopen(req, timeout=12) as r:
                return "sent", "Twilio accepted it (HTTP %s)" % r.status
        return "failed", "unknown provider"
    except HTTPError as e:
        return "failed", "provider returned HTTP %s" % e.code
    except URLError:
        return "failed", "network error: could not reach the provider"
    except Exception:
        app.logger.exception("alert send failed")
        return "failed", "unexpected error"


def _send_job(aid, s, text):
    status, detail = send_whatsapp(s, text)
    run("UPDATE alerts SET status=?, detail=? WHERE id=?", (status, detail, aid))


def new_alert(kind, fp, provider, status, msg, detail=""):
    cur = run("INSERT INTO alerts(created_at,kind,fp,provider,status,detail,message) VALUES(?,?,?,?,?,?,?)",
              (datetime.now(timezone.utc).isoformat(timespec="seconds"), kind, fp, provider, status, detail, msg))
    return cur.lastrowid


def dispatch_alert(res, kind, subject, fp=None, force=False):
    s = get_settings()
    if not force and (s["enabled"] != "1" or s["consent"] != "1"):
        return {"state": "not_configured"}
    if not s["caretaker_phone"]:
        return {"state": "not_configured"}
    msg = build_alert_message(res, kind, subject, s)
    if s["provider"] == "link":
        aid = new_alert(kind, fp, "link", "needs_tap", msg, "waiting for you to tap Send in WhatsApp")
        return {"state": "needs_tap", "id": aid,
                "wa_link": "https://wa.me/%s?text=%s" % (s["caretaker_phone"].lstrip("+"), quote(msg))}
    if s["provider"] == "callmebot" and not s["callmebot_apikey"]:
        return {"state": "not_configured"}
    if s["provider"] == "twilio" and not twilio_ready():
        return {"state": "not_configured"}
    if fp and not force:  # do not spam the caretaker about the same link within 10 minutes
        rows = run("SELECT created_at FROM alerts WHERE fp=? AND status IN ('sent','sending') ORDER BY id DESC LIMIT 1",
                   (fp,), fetch=True)
        if rows:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(rows[0]["created_at"])).total_seconds()
            if age < 600:
                return {"state": "recent"}
    aid = new_alert(kind, fp, s["provider"], "sending", msg, "sending...")
    threading.Thread(target=_send_job, args=(aid, dict(s), msg), daemon=True).start()
    return {"state": "sending", "id": aid}


def maybe_alert(res, kind, subject):
    """Called after every scan. Only HIGH risk results are blocked and reported."""
    res["blocked"] = res["risk"] == "HIGH"
    if not res["blocked"]:
        return res
    try:
        res["alert"] = dispatch_alert(res, kind, subject, fp=subject if kind in ("url", "qr") else None)
    except Exception:
        app.logger.exception("alert dispatch failed")
        res["alert"] = {"state": "failed"}
    return res


# ---------- routes ----------
@app.get("/")
@app.get("/index.html")
def home():
    p = os.path.join(BASE, "index.html")
    if not os.path.isfile(p):
        return "index.html not found next to app.py", 404
    return send_file(p, max_age=0)


@app.get("/settings")
def settings_get():
    return jsonify(public_settings(get_settings()))


@app.post("/settings")
def settings_save():
    d = request.get_json(silent=True) or {}
    new = get_settings()
    clean = lambda v, n=60: re.sub(r"[\r\n\t]", " ", str(v or "")).strip()[:n]
    for k in ("user_name", "caretaker_name"):
        if k in d:
            new[k] = clean(d[k])
    if "caretaker_phone" in d:
        p = re.sub(r"[\s\-()]", "", str(d["caretaker_phone"] or ""))
        if p and not PHONE_RE.match(p):
            return fail("Enter the number with country code, like +919876543210.", "bad_phone")
        new["caretaker_phone"] = p
    if "language" in d:
        new["language"] = "hi" if d["language"] == "hi" else "en"
    if "provider" in d:
        if d["provider"] not in ("link", "callmebot", "twilio"):
            return fail("Choose how to send.", "bad_provider")
        new["provider"] = d["provider"]
    key = clean(d.get("callmebot_apikey"), 40)
    if key:
        if not re.fullmatch(r"[A-Za-z0-9]+", key):
            return fail("The API key has only letters and numbers.", "bad_apikey")
        new["callmebot_apikey"] = key
    if "enabled" in d:
        new["enabled"] = "1" if d["enabled"] is True else "0"
    if "consent" in d:
        new["consent"] = "1" if d["consent"] is True else "0"
    if new["enabled"] == "1":
        if new["consent"] != "1":
            return fail("Please tick the consent box to turn alerts on.", "consent_required")
        if not new["caretaker_phone"]:
            return fail("Enter the caretaker's WhatsApp number.", "bad_phone")
        if new["provider"] == "callmebot" and not new["callmebot_apikey"]:
            return fail("Enter the CallMeBot API key.", "need_apikey")
        if new["provider"] == "twilio" and not twilio_ready():
            return fail("Twilio is not set up on the server.", "twilio_not_configured")
    for k, v in new.items():
        run("INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))
    return jsonify(public_settings(new))


@app.post("/test-alert")
def test_alert():
    s = get_settings()
    if not s["caretaker_phone"] or s["consent"] != "1":
        return jsonify({"state": "not_configured"})
    fake = {"risk": "HIGH", "findings": [{"c": "otp", "d": ""}, {"c": "urgency", "d": ""}, {"c": "click", "d": ""},
                                          {"c": "u_short", "d": ""}]}
    out = dispatch_alert(fake, "sms", "", force=True)
    return jsonify(out)


@app.get("/alerts")
def alerts_list():
    rows = run("SELECT id, created_at, kind, provider, status, detail FROM alerts ORDER BY id DESC LIMIT 20", fetch=True)
    return jsonify([dict(r) for r in rows])


@app.get("/health")
def health():
    return jsonify({"status": "ok", "safe_browsing_configured": bool(API_KEY), "gmail_connected": False,
                    "qr_decoder": cv2 is not None, "ocr_engine": find_tesseract() is not None})


@app.post("/check")
def check():
    raw, d = get_json_field("url", maxlen=2100)
    if not raw:
        return fail("Please enter a link.", "empty_url")
    url = normalize_url(raw)
    if not url:
        return fail("Please enter a valid http/https link.", "bad_url")
    res = scan_url(url)
    stype = "qr" if d.get("source") == "qr" else "url"
    res.update({"id": save_scan(stype, url, res), "scan_type": stype, "subject": url, "verdict": verdict_for(res)})
    return jsonify(maybe_alert(res, stype, url))


@app.post("/analyze-message")
def analyze_message():
    text, d = get_json_field("text", "message", "email")
    if not text:
        return fail("Please paste some text to analyze.", "empty_text")
    if len(text) < 5:
        return fail("The text is too short to analyze.", "short_text")
    stype = d.get("type") if d.get("type") in ("sms", "message", "email") else "message"
    res = analyze_text(text, stype == "email")
    subject = "%s (%d chars, text not stored)" % (stype.upper(), len(text))
    if d.get("save_content") is True:  # stored only on explicit opt-in
        subject = text[:200]
    res.update({"id": save_scan(stype, subject, res), "scan_type": stype, "subject": subject})
    return jsonify(maybe_alert(res, stype, subject))


@app.get("/history")
def history():
    rows = run("SELECT * FROM scans ORDER BY id DESC LIMIT 200", fetch=True)
    return jsonify([{"id": r["id"], "scan_type": r["scan_type"], "subject": r["subject"], "risk": r["risk"],
                     "score": r["score"], "status": r["status"], "findings": json.loads(r["findings"] or "[]"),
                     "created_at": r["created_at"]} for r in rows])


@app.delete("/history/<int:sid>")
def delete_one(sid):
    if run("DELETE FROM scans WHERE id=?", (sid,)).rowcount:
        return jsonify({"deleted": sid})
    return fail("Record not found.", "not_found", 404)


@app.delete("/history")
def delete_all():
    return jsonify({"deleted_count": run("DELETE FROM scans").rowcount})


@app.get("/dashboard")
def dashboard():
    r = run("SELECT COUNT(*) t, SUM(risk='HIGH') h, SUM(risk='MEDIUM') m, SUM(risk='LOW') l FROM scans", fetch=True)[0]
    types = {x["scan_type"]: x["c"] for x in run("SELECT scan_type, COUNT(*) c FROM scans GROUP BY scan_type", fetch=True)}
    return jsonify({"total": r["t"] or 0, "high": r["h"] or 0, "medium": r["m"] or 0, "low": r["l"] or 0,
                    "by_type": {k: types.get(k, 0) for k in ("url", "qr", "screenshot", "sms", "message", "email")}})


TIPS = [
    {"icon": "\U0001F3A3", "en": ["Phishing awareness", "Check the sender's real address, not just the display name. Hover over links before you click."],
     "hi": ["फ़िशिंग से सावधानी", "सिर्फ़ दिखने वाले नाम नहीं, प्रेषक का असली पता जाँचें। क्लिक से पहले लिंक पर माउस ले जाकर देखें।"]},
    {"icon": "\U0001F510", "en": ["Never share your OTP", "Banks and government offices never ask for your OTP, PIN, CVV or password, not even on a call."],
     "hi": ["OTP कभी साझा न करें", "बैंक और सरकारी विभाग आपसे OTP, PIN, CVV या पासवर्ड कभी नहीं माँगते, फ़ोन पर भी नहीं।"]},
    {"icon": "\U0001F4B8", "en": ["Payment request red flags", "You never need a UPI PIN to receive money. Reject collect requests you did not expect."],
     "hi": ["भुगतान माँग के खतरे के संकेत", "पैसे पाने के लिए UPI PIN की ज़रूरत नहीं होती। अनचाहे कलेक्ट रिक्वेस्ट अस्वीकार करें।"]},
    {"icon": "\U0001F4F7", "en": ["QR code safety", "Scanning a QR code to receive money is always a scam. Check where a QR leads before logging in."],
     "hi": ["QR कोड सुरक्षा", "पैसे पाने के लिए QR स्कैन करना हमेशा ठगी है। लॉगिन से पहले देखें कि QR कहाँ ले जा रहा है।"]},
    {"icon": "\U0001F310", "en": ["Safe browsing", "Type official addresses yourself or use the official app. HTTPS alone does not prove a site is safe."],
     "hi": ["सुरक्षित ब्राउज़िंग", "आधिकारिक पता खुद टाइप करें या आधिकारिक ऐप चलाएँ। सिर्फ़ HTTPS होने से साइट सुरक्षित नहीं हो जाती।"]},
    {"icon": "\U0001F4DE", "en": ["Report scams (India)", "Call 1930 for financial fraud, report at cybercrime.gov.in, and forward spam SMS to 1909."],
     "hi": ["ठगी की शिकायत (भारत)", "वित्तीय धोखाधड़ी पर 1930 पर कॉल करें, cybercrime.gov.in पर शिकायत करें और स्पैम SMS 1909 पर भेजें।"]},
    {"icon": "\U0001F6A8", "en": ["Clicked a bad link?", "Disconnect, scan your device, change passwords from a clean device, and call your bank at once if you shared details."],
     "hi": ["गलत लिंक पर क्लिक हो गया?", "इंटरनेट बंद करें, डिवाइस स्कैन करें, साफ़ डिवाइस से पासवर्ड बदलें और जानकारी दी हो तो तुरंत बैंक को कॉल करें।"]},
    {"icon": "\U0001F6E1", "en": ["Use two-step verification", "Turn it on for email, banking and social accounts, and use a unique password for each."],
     "hi": ["टू-स्टेप वेरिफ़िकेशन चालू रखें", "ईमेल, बैंकिंग और सोशल अकाउंट पर इसे चालू करें और हर खाते का अलग पासवर्ड रखें।"]},
]


@app.get("/safety-tips")
def safety_tips():
    tips = TIPS[:]
    random.shuffle(tips)
    return jsonify(tips)


@app.errorhandler(404)
def not_found(e):
    return fail("Not found.", "not_found", 404)


@app.errorhandler(413)
def too_big(e):
    return fail("Request too large.", "too_big", 413)


@app.errorhandler(500)
def server_error(e):
    return fail("Internal server error.", "server", 500)


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=True)