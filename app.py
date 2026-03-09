from flask import Flask, render_template, request, redirect, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from functools import wraps
import sqlite3
import datetime
import random
import time
import os
import requests
import hashlib
import uuid
import json

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

from datetime import timedelta
app.permanent_session_lifetime = timedelta(minutes=30)

DATABASE         = "database.db"
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
SENDER_EMAIL     = os.getenv("SENDER_EMAIL")
API_KEY          = os.getenv("API_KEY")

# ================================================================
#  DB CONNECTION
# ================================================================
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# ================================================================
#  API KEY AUTH DECORATOR
# ================================================================
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key')
        if not key or key != API_KEY:
            return jsonify({
                "success": False,
                "error": "Unauthorized — Invalid or missing API Key",
                "hint": "Pass your key in header: X-API-Key: your_key"
            }), 401
        return f(*args, **kwargs)
    return decorated

# ================================================================
#  SEND OTP EMAIL
# ================================================================
def send_otp_email(to_email, otp, username):
    try:
        html_content = f"""
        <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; background: #0e0f1a; color: #e2e8f0; padding: 40px; border-radius: 16px;">
            <div style="text-align: center; margin-bottom: 30px;">
                <div style="font-size: 40px;">🛡️</div>
                <h2 style="color: #a78bfa; font-size: 22px; margin-top: 10px;">Zero Trust Security</h2>
            </div>
            <p style="color: #94a3b8; margin-bottom: 10px;">Hello <strong style="color: #fff;">{username}</strong>,</p>
            <p style="color: #94a3b8; margin-bottom: 24px;">A login attempt was detected. Use the OTP below to verify your identity:</p>
            <div style="background: #181930; border: 2px solid #6c63ff; border-radius: 12px; padding: 24px; text-align: center; margin-bottom: 24px;">
                <div style="font-size: 42px; font-weight: 800; letter-spacing: 12px; color: #a78bfa;">{otp}</div>
                <p style="color: #64748b; font-size: 12px; margin-top: 10px;">Valid for 5 minutes only</p>
            </div>
            <p style="color: #64748b; font-size: 12px; text-align: center;">If you did not attempt to login, please ignore this email.</p>
        </div>
        """
        message = Mail(from_email=SENDER_EMAIL, to_emails=to_email,
                       subject='🔐 Your Zero Trust Login OTP', html_content=html_content)
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        sg.send(message)
        print(f"\n📧 OTP email sent to {to_email}\n")
        return True
    except Exception as e:
        print(f"\n❌ Email failed: {e}")
        print(f"🔐 Fallback OTP for {username}: {otp}\n")
        return False

# ================================================================
#  HELPERS
# ================================================================
def get_location(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        d = r.json()
        if d.get("status") == "success":
            return f"{d.get('city','Unknown')}, {d.get('country','Unknown')}"
        return "Unknown"
    except: return "Unknown"

def get_device_fingerprint(req):
    ua   = req.headers.get('User-Agent', '')
    lang = req.headers.get('Accept-Language', '')
    fp   = hashlib.md5(f"{ua}{lang}".encode()).hexdigest()[:12]
    device  = next((d for d in ["Windows","Mac","Linux","Android","iPhone"] if d in ua), "Unknown")
    browser = "Edge" if "Edg" in ua else next((b for b in ["Chrome","Firefox","Safari"] if b in ua), "Unknown")
    return f"{device} / {browser}", fp

def check_time_anomaly(username, current_hour):
    conn = get_db(); cursor = conn.cursor()
    cursor.execute("SELECT hour FROM login_history WHERE username=? ORDER BY id DESC LIMIT 10", (username,))
    rows = cursor.fetchall(); conn.close()
    if len(rows) < 3: return False
    hours = [r['hour'] for r in rows]
    avg   = sum(hours) / len(hours)
    diff  = abs(current_hour - avg)
    if diff > 12: diff = 24 - diff
    return diff > 6

def check_concurrent_session(username, new_sid):
    conn = get_db(); cursor = conn.cursor()
    cursor.execute("SELECT session_id FROM active_sessions WHERE username=?", (username,))
    row = cursor.fetchone()
    existed = row and row['session_id'] != new_sid
    cursor.execute("REPLACE INTO active_sessions (username, session_id, timestamp) VALUES (?,?,?)",
                   (username, new_sid, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit(); conn.close()
    return existed

def analyze_typing(typing_speed, typing_pattern, is_paste, current_hour, failed_attempts, is_time_anomaly):
    try:
        is_paste = str(is_paste) == "1"
        if is_paste:
            signals = []
            if 0 <= current_hour <= 5: signals.append("late night")
            if failed_attempts >= 2:   signals.append(f"{failed_attempts} prior failures")
            if is_time_anomaly:        signals.append("unusual login time")
            if signals: return True, f"Paste+Context ({', '.join(signals)})"
            return False, "Paste/Password Manager"
        if not typing_pattern: return False, "No Data"
        p = json.loads(typing_pattern)
        avg = p.get('avg', 999); min_i = p.get('min', 999)
        if avg < 50 or min_i < 20: return True, f"Bot Speed ({avg}ms avg)"
        if 50 <= avg <= 800:       return False, f"Normal ({avg}ms avg)"
        if avg > 2000 and p.get('count',0) > 3: return True, f"Too Slow ({avg}ms avg)"
        return False, f"Normal ({avg}ms avg)"
    except: return False, "No Data"

def calculate_risk(username, failed_attempts, typing_suspicious, typing_label,
                   current_hour, is_time_anomaly):
    risk = "Low"; reasons = []
    if failed_attempts >= 5:
        risk = "High"; reasons.append("Too many failed attempts")
    elif failed_attempts >= 3:
        risk = "Medium"; reasons.append("Multiple failed attempts")
    if typing_suspicious:
        risk = "Medium" if risk == "Low" else risk
        reasons.append(typing_label)
    if is_time_anomaly and "unusual login time" not in " ".join(reasons):
        risk = "Medium" if risk == "Low" else risk
        reasons.append("Unusual login time")
    if 0 <= current_hour <= 5 and risk == "Low":
        risk = "Medium"; reasons.append("Late night login")
    return risk, reasons

# ================================================================
#  DATABASE INIT
# ================================================================
def init_db():
    conn = sqlite3.connect(DATABASE); cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE,
        password TEXT, email TEXT, role TEXT DEFAULT 'user',
        failed_attempts INTEGER DEFAULT 0, lock_until TEXT, is_banned INTEGER DEFAULT 0)""")
    for col in ["email TEXT", "is_banned INTEGER DEFAULT 0"]:
        try: cursor.execute(f"ALTER TABLE users ADD COLUMN {col}")
        except: pass
    cursor.execute("""CREATE TABLE IF NOT EXISTS login_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, risk_level TEXT,
        status TEXT, timestamp TEXT, location TEXT DEFAULT 'Unknown',
        device_info TEXT DEFAULT 'Unknown', typing_flag TEXT DEFAULT 'No Data')""")
    for col in ["device_info TEXT DEFAULT 'Unknown'", "typing_flag TEXT DEFAULT 'No Data'"]:
        try: cursor.execute(f"ALTER TABLE login_logs ADD COLUMN {col}")
        except: pass
    cursor.execute("""CREATE TABLE IF NOT EXISTS ip_blocks (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ip_address TEXT,
        failed_attempts INTEGER DEFAULT 0, lock_until TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS login_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, hour INTEGER, timestamp TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS active_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE,
        session_id TEXT, timestamp TEXT)""")

    # ✅ Default admin — init_db ke andar
    cursor.execute("SELECT * FROM users WHERE username='admin'")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO users (username, password, email, role) VALUES (?,?,?,?)",
            ('admin', generate_password_hash('admin123'), 'admin@zerotrust.com', 'admin'))
        print("✅ Default admin created!")

    conn.commit()
    conn.close()

# ✅ Gunicorn ke liye — if __name__ se BAHAR
init_db()

# ================================================================
#  WEB ROUTES
# ================================================================
@app.route('/')
def home(): return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if request.form.get('website', ''): return render_template('message.html', msg_type="blocked", message="Bot detected!")
        username = request.form['username']; email = request.form['email']
        password = generate_password_hash(request.form['password'])
        conn = get_db(); cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password, email) VALUES (?,?,?)", (username, password, email))
            conn.commit()
        except: conn.close(); return render_template('message.html', msg_type="error", message="User already exists!")
        conn.close(); return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('website', ''): return render_template('message.html', msg_type="blocked", message="Bot detected!")
        username = request.form['username']; password = request.form['password']
        ip_address = request.remote_addr; location = get_location(ip_address)
        device_info, _ = get_device_fingerprint(request)
        typing_speed = request.form.get('typing_speed',''); typing_pattern = request.form.get('typing_pattern','')
        is_paste = request.form.get('is_paste','0')
        conn = get_db(); cursor = conn.cursor()
        cursor.execute("SELECT failed_attempts, lock_until FROM ip_blocks WHERE ip_address=?", (ip_address,))
        ip_record = cursor.fetchone(); ip_failed = ip_record['failed_attempts'] if ip_record else 0
        if ip_record and ip_record['lock_until']:
            lt = datetime.datetime.strptime(ip_record['lock_until'], "%Y-%m-%d %H:%M:%S")
            if datetime.datetime.now() < lt: conn.close(); return render_template('message.html', msg_type="blocked", message=f"IP blocked until {ip_record['lock_until']}.")
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        if not user: conn.close(); return render_template('message.html', msg_type="error", message="User not found!")
        stored_pw = user['password']; user_email = user['email']
        failed_attempts = user['failed_attempts']; lock_until = user['lock_until']; is_banned = user['is_banned']
        if is_banned: conn.close(); return render_template('message.html', msg_type="blocked", message="Account banned.")
        if lock_until:
            lt = datetime.datetime.strptime(lock_until, "%Y-%m-%d %H:%M:%S")
            if datetime.datetime.now() < lt: conn.close(); return render_template('message.html', msg_type="blocked", message=f"Account locked until {lock_until}.")
        if not check_password_hash(stored_pw, password):
            failed_attempts += 1; ip_failed += 1
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("UPDATE users SET failed_attempts=? WHERE username=?", (failed_attempts, username))
            if ip_record: cursor.execute("UPDATE ip_blocks SET failed_attempts=? WHERE ip_address=?", (ip_failed, ip_address))
            else: cursor.execute("INSERT INTO ip_blocks (ip_address, failed_attempts) VALUES (?,?)", (ip_address, ip_failed))
            if ip_failed >= 10:
                lt = (datetime.datetime.now() + datetime.timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("UPDATE ip_blocks SET lock_until=? WHERE ip_address=?", (lt, ip_address))
            cursor.execute("INSERT INTO login_logs (username, risk_level, status, timestamp, location, device_info, typing_flag) VALUES (?,?,?,?,?,?,?)",
                           (username, "Low", "Wrong Password", ts, location, device_info, "No Data"))
            conn.commit(); conn.close()
            return render_template('message.html', msg_type="error", message=f"Wrong password! {max(0,5-failed_attempts)} attempts remaining.")
        current_hour = datetime.datetime.now().hour; ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        is_time_anomaly = check_time_anomaly(username, current_hour)
        typing_suspicious, typing_label = analyze_typing(typing_speed, typing_pattern, is_paste, current_hour, failed_attempts, is_time_anomaly)
        risk, risk_reasons = calculate_risk(username, failed_attempts, typing_suspicious, typing_label, current_hour, is_time_anomaly)
        cursor.execute("INSERT INTO login_history (username, hour, timestamp) VALUES (?,?,?)", (username, current_hour, ts))
        if risk == "High":
            lt = (datetime.datetime.now() + datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("UPDATE users SET lock_until=? WHERE username=?", (lt, username))
            cursor.execute("INSERT INTO login_logs (username, risk_level, status, timestamp, location, device_info, typing_flag) VALUES (?,?,?,?,?,?,?)",
                           (username, "High", "Account Locked", ts, location, device_info, typing_label))
            conn.commit(); conn.close()
            return render_template('message.html', msg_type="blocked", message=f"High risk! Locked until {lt}. Reasons: {', '.join(risk_reasons)}")
        if risk == "Medium":
            cursor.execute("INSERT INTO login_logs (username, risk_level, status, timestamp, location, device_info, typing_flag) VALUES (?,?,?,?,?,?,?)",
                           (username, "Medium", "OTP Required", ts, location, device_info, typing_label))
            conn.commit()
            otp = str(random.randint(100000, 999999))
            session['otp'] = otp; session['otp_expiry'] = time.time() + 300; session['temp_user'] = username
            if user_email: send_otp_email(user_email, otp, username)
            else: print(f"\n🔐 OTP: {otp}\n")
            conn.close(); return redirect('/verify-otp')
        cursor.execute("UPDATE users SET failed_attempts=0, lock_until=NULL WHERE username=?", (username,))
        cursor.execute("INSERT INTO login_logs (username, risk_level, status, timestamp, location, device_info, typing_flag) VALUES (?,?,?,?,?,?,?)",
                       (username, "Low", "Success", ts, location, device_info, typing_label))
        conn.commit(); conn.close()
        new_sid = str(uuid.uuid4()); session.permanent = True
        session['username'] = username; session['session_id'] = new_sid
        session['ip'] = ip_address; session['ua'] = request.headers.get('User-Agent','')
        check_concurrent_session(username, new_sid)
        return redirect('/dashboard')
    return render_template('login.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp' not in session: return redirect('/login')
    if request.method == 'POST':
        entered = request.form['otp']
        if time.time() > session.get('otp_expiry', 0):
            session.pop('otp',None); session.pop('otp_expiry',None); session.pop('temp_user',None)
            return render_template('message.html', msg_type="otp_error", message="OTP expired!")
        if entered == session['otp']:
            username = session['temp_user']
            conn = get_db(); cursor = conn.cursor()
            cursor.execute("UPDATE users SET failed_attempts=0 WHERE username=?", (username,))
            conn.commit(); conn.close()
            session.pop('otp',None); session.pop('otp_expiry',None); session.pop('temp_user',None)
            new_sid = str(uuid.uuid4()); session.permanent = True
            session['username'] = username; session['session_id'] = new_sid
            session['ip'] = request.remote_addr; session['ua'] = request.headers.get('User-Agent','')
            check_concurrent_session(username, new_sid)
            return redirect('/dashboard')
        return render_template('message.html', msg_type="otp_error", message="Invalid OTP!")
    return render_template('verify_otp.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session: return redirect('/login')
    session.permanent = True
    conn = get_db(); cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username=?", (session['username'],))
    row = cursor.fetchone(); conn.close()
    return redirect('/admin' if row and row['role'] == 'admin' else '/portal')

@app.route('/admin')
def admin_panel():
    if 'username' not in session: return redirect('/login')
    conn = get_db(); cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username=?", (session['username'],))
    if cursor.fetchone()['role'] != 'admin': conn.close(); return render_template('message.html', msg_type="error", message="Access Denied!")
    cursor.execute("SELECT username, risk_level, status, timestamp, location, device_info, typing_flag FROM login_logs ORDER BY id DESC LIMIT 20")
    logs = cursor.fetchall()
    cursor.execute("SELECT COUNT(*) as c FROM login_logs"); total_logins = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM login_logs WHERE status='Wrong Password'"); total_failures = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM ip_blocks WHERE lock_until IS NOT NULL"); active_ip_blocks = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM users WHERE is_banned=1"); total_banned = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM login_logs WHERE risk_level='Low'"); low_count = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM login_logs WHERE risk_level='Medium'"); medium_count = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM login_logs WHERE risk_level='High'"); high_count = cursor.fetchone()['c']
    labels, daily_counts = [], []
    for i in range(6, -1, -1):
        day = (datetime.datetime.now() - datetime.timedelta(days=i)).strftime("%Y-%m-%d")
        label = (datetime.datetime.now() - datetime.timedelta(days=i)).strftime("%d %b")
        cursor.execute("SELECT COUNT(*) as c FROM login_logs WHERE timestamp LIKE ?", (f"{day}%",))
        labels.append(label); daily_counts.append(cursor.fetchone()['c'])
    cursor.execute("SELECT ip_address, failed_attempts, lock_until FROM ip_blocks WHERE lock_until IS NOT NULL ORDER BY id DESC")
    blocked_ips = cursor.fetchall()
    cursor.execute("SELECT id, username, role, failed_attempts, lock_until, is_banned FROM users ORDER BY id DESC")
    all_users = cursor.fetchall()
    cursor.execute("SELECT username, status, timestamp, location FROM login_logs WHERE risk_level='High' ORDER BY id DESC LIMIT 5")
    alerts = cursor.fetchall(); conn.close()
    return render_template('admin.html', user=session['username'], logs=logs,
        total_logins=total_logins, total_failures=total_failures, active_ip_blocks=active_ip_blocks,
        total_banned=total_banned, low_count=low_count, medium_count=medium_count, high_count=high_count,
        chart_labels=labels, daily_counts=daily_counts, blocked_ips=blocked_ips, all_users=all_users, alerts=alerts)

@app.route('/portal')
def user_portal():
    if 'username' not in session: return redirect('/login')
    session.permanent = True; username = session['username']
    conn = get_db(); cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username=?", (username,))
    if cursor.fetchone()['role'] == 'admin': conn.close(); return redirect('/admin')
    cursor.execute("SELECT username, risk_level, status, timestamp, location, device_info FROM login_logs WHERE username=? ORDER BY id DESC LIMIT 10", (username,))
    logs = cursor.fetchall()
    cursor.execute("SELECT COUNT(*) as c FROM login_logs WHERE username=?", (username,)); total_logins = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM login_logs WHERE username=? AND status='Wrong Password'", (username,)); total_failures = cursor.fetchone()['c']
    cursor.execute("SELECT failed_attempts, lock_until FROM users WHERE username=?", (username,)); user_info = cursor.fetchone()
    conn.close()
    return render_template('user_portal.html', user=username, logs=logs,
        total_logins=total_logins, total_failures=total_failures,
        failed_attempts=user_info['failed_attempts'], lock_until=user_info['lock_until'])

@app.route('/admin/ban/<int:uid>')
def ban_user(uid):
    if 'username' not in session: return redirect('/login')
    conn = get_db(); cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username=?", (session['username'],))
    if cursor.fetchone()['role'] != 'admin': conn.close(); return render_template('message.html', msg_type="error", message="Access Denied!")
    cursor.execute("UPDATE users SET is_banned=1 WHERE id=?", (uid,)); conn.commit(); conn.close()
    return redirect('/admin')

@app.route('/admin/unban/<int:uid>')
def unban_user(uid):
    if 'username' not in session: return redirect('/login')
    conn = get_db(); cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username=?", (session['username'],))
    if cursor.fetchone()['role'] != 'admin': conn.close(); return render_template('message.html', msg_type="error", message="Access Denied!")
    cursor.execute("UPDATE users SET is_banned=0, failed_attempts=0, lock_until=NULL WHERE id=?", (uid,)); conn.commit(); conn.close()
    return redirect('/admin')

@app.route('/admin/unblock/<ip>')
def unblock_ip(ip):
    if 'username' not in session: return redirect('/login')
    conn = get_db(); cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username=?", (session['username'],))
    if cursor.fetchone()['role'] != 'admin': conn.close(); return render_template('message.html', msg_type="error", message="Access Denied!")
    cursor.execute("UPDATE ip_blocks SET lock_until=NULL, failed_attempts=0 WHERE ip_address=?", (ip,)); conn.commit(); conn.close()
    return redirect('/admin')

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session: return redirect('/login')
    if request.method == 'POST':
        step = request.form.get('step')
        if step == 'request_otp':
            otp = str(random.randint(100000, 999999))
            session['pwd_otp'] = otp; session['pwd_otp_expiry'] = time.time() + 300
            conn = get_db(); cursor = conn.cursor()
            cursor.execute("SELECT email FROM users WHERE username=?", (session['username'],))
            row = cursor.fetchone(); conn.close()
            if row and row['email']: send_otp_email(row['email'], otp, session['username'])
            else: print(f"\n🔐 Password Change OTP: {otp}\n")
            return render_template('change_password.html', step='verify_otp')
        elif step == 'verify_otp':
            if time.time() > session.get('pwd_otp_expiry', 0):
                session.pop('pwd_otp', None)
                return render_template('message.html', msg_type="otp_error", message="OTP expired!")
            if request.form.get('otp') != session.get('pwd_otp'):
                return render_template('message.html', msg_type="otp_error", message="Invalid OTP!")
            session.pop('pwd_otp', None)
            return render_template('change_password.html', step='new_password')
        elif step == 'new_password':
            np = request.form.get('new_password'); cp = request.form.get('confirm_password')
            if np != cp: return render_template('message.html', msg_type="error", message="Passwords do not match!")
            conn = get_db(); cursor = conn.cursor()
            cursor.execute("UPDATE users SET password=? WHERE username=?", (generate_password_hash(np), session['username']))
            conn.commit(); conn.close()
            return render_template('message.html', msg_type="success", message="Password changed successfully!")
    return render_template('change_password.html', step='request_otp')

@app.route('/logout')
def logout():
    username = session.get('username')
    if username:
        conn = get_db(); cursor = conn.cursor()
        cursor.execute("DELETE FROM active_sessions WHERE username=?", (username,))
        conn.commit(); conn.close()
    session.clear(); return redirect('/login')


# ================================================================
#  🔌 REST API ROUTES
# ================================================================

@app.route('/api/health', methods=['GET'])
def api_health():
    return jsonify({
        "success": True,
        "status": "Zero Trust Security API is running! 🛡️",
        "version": "1.0",
        "endpoints": [
            "POST /api/login       — Risk check",
            "GET  /api/logs        — Login logs",
            "GET  /api/users       — All users",
            "GET  /api/stats       — Dashboard stats",
            "POST /api/ban         — Ban a user",
            "POST /api/unban       — Unban a user",
            "POST /api/unblock-ip  — Unblock an IP"
        ]
    })

@app.route('/api/login', methods=['POST'])
@require_api_key
def api_login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"success": False, "error": "username and password required"}), 400
    username = data['username']; password = data['password']
    ip_address = request.remote_addr
    conn = get_db(); cursor = conn.cursor()
    cursor.execute("SELECT failed_attempts, lock_until FROM ip_blocks WHERE ip_address=?", (ip_address,))
    ip_record = cursor.fetchone()
    if ip_record and ip_record['lock_until']:
        lt = datetime.datetime.strptime(ip_record['lock_until'], "%Y-%m-%d %H:%M:%S")
        if datetime.datetime.now() < lt:
            conn.close()
            return jsonify({"success": False, "error": "IP blocked", "blocked_until": ip_record['lock_until']}), 403
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    if not user: conn.close(); return jsonify({"success": False, "error": "User not found"}), 404
    if user['is_banned']: conn.close(); return jsonify({"success": False, "error": "Account banned"}), 403
    if user['lock_until']:
        lt = datetime.datetime.strptime(user['lock_until'], "%Y-%m-%d %H:%M:%S")
        if datetime.datetime.now() < lt:
            conn.close()
            return jsonify({"success": False, "error": "Account locked", "locked_until": user['lock_until']}), 403
    if not check_password_hash(user['password'], password):
        failed = user['failed_attempts'] + 1
        cursor.execute("UPDATE users SET failed_attempts=? WHERE username=?", (failed, username))
        conn.commit(); conn.close()
        return jsonify({"success": False, "error": "Wrong password", "attempts_remaining": max(0, 5-failed)}), 401
    current_hour    = datetime.datetime.now().hour
    is_time_anomaly = check_time_anomaly(username, current_hour)
    typing_suspicious, typing_label = analyze_typing('', '', '0', current_hour, user['failed_attempts'], is_time_anomaly)
    risk, reasons = calculate_risk(username, user['failed_attempts'], typing_suspicious, typing_label, current_hour, is_time_anomaly)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO login_history (username, hour, timestamp) VALUES (?,?,?)", (username, current_hour, ts))
    cursor.execute("INSERT INTO login_logs (username, risk_level, status, timestamp, location, device_info, typing_flag) VALUES (?,?,?,?,?,?,?)",
                   (username, risk, f"API-{risk}", ts, "API Call", "API Client", typing_label))
    cursor.execute("UPDATE users SET failed_attempts=0 WHERE username=?", (username,))
    conn.commit(); conn.close()
    return jsonify({
        "success": True, "username": username, "risk_level": risk,
        "risk_reasons": reasons,
        "action": "ALLOW" if risk == "Low" else "REQUIRE_OTP" if risk == "Medium" else "BLOCK",
        "timestamp": ts
    })

@app.route('/api/logs', methods=['GET'])
@require_api_key
def api_logs():
    limit = request.args.get('limit', 20, type=int)
    conn = get_db(); cursor = conn.cursor()
    cursor.execute("SELECT username, risk_level, status, timestamp, location, device_info, typing_flag FROM login_logs ORDER BY id DESC LIMIT ?", (limit,))
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({"success": True, "count": len(logs), "logs": logs})

@app.route('/api/users', methods=['GET'])
@require_api_key
def api_users():
    conn = get_db(); cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, failed_attempts, lock_until, is_banned FROM users ORDER BY id DESC")
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({"success": True, "count": len(users), "users": users})

@app.route('/api/stats', methods=['GET'])
@require_api_key
def api_stats():
    conn = get_db(); cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as c FROM login_logs"); total = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM login_logs WHERE status='Wrong Password'"); failures = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM ip_blocks WHERE lock_until IS NOT NULL"); blocked_ips = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM users WHERE is_banned=1"); banned = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM login_logs WHERE risk_level='Low'"); low = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM login_logs WHERE risk_level='Medium'"); medium = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM login_logs WHERE risk_level='High'"); high = cursor.fetchone()['c']
    conn.close()
    return jsonify({
        "success": True,
        "stats": {
            "total_logins": total, "failed_attempts": failures,
            "blocked_ips": blocked_ips, "banned_users": banned,
            "risk_distribution": {"Low": low, "Medium": medium, "High": high}
        }
    })

@app.route('/api/ban', methods=['POST'])
@require_api_key
def api_ban():
    data = request.get_json()
    if not data or 'username' not in data:
        return jsonify({"success": False, "error": "username required"}), 400
    conn = get_db(); cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_banned=1 WHERE username=?", (data['username'],))
    if cursor.rowcount == 0: conn.close(); return jsonify({"success": False, "error": "User not found"}), 404
    conn.commit(); conn.close()
    return jsonify({"success": True, "message": f"User '{data['username']}' banned!"})

@app.route('/api/unban', methods=['POST'])
@require_api_key
def api_unban():
    data = request.get_json()
    if not data or 'username' not in data:
        return jsonify({"success": False, "error": "username required"}), 400
    conn = get_db(); cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_banned=0, failed_attempts=0, lock_until=NULL WHERE username=?", (data['username'],))
    if cursor.rowcount == 0: conn.close(); return jsonify({"success": False, "error": "User not found"}), 404
    conn.commit(); conn.close()
    return jsonify({"success": True, "message": f"User '{data['username']}' unbanned!"})

@app.route('/api/unblock-ip', methods=['POST'])
@require_api_key
def api_unblock_ip():
    data = request.get_json()
    if not data or 'ip' not in data:
        return jsonify({"success": False, "error": "ip required"}), 400
    conn = get_db(); cursor = conn.cursor()
    cursor.execute("UPDATE ip_blocks SET lock_until=NULL, failed_attempts=0 WHERE ip_address=?", (data['ip'],))
    conn.commit(); conn.close()
    return jsonify({"success": True, "message": f"IP '{data['ip']}' unblocked!"})


# ================================================================
#  RUN
# ================================================================
if __name__ == "__main__":
    app.run(debug=True)