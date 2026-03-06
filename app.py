from flask import Flask, render_template, request, redirect, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import sqlite3
import datetime
import random
import time
import os
import requests
import hashlib
import uuid

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

from datetime import timedelta
app.permanent_session_lifetime = timedelta(minutes=30)

DATABASE = "database.db"

# ---------------- GET LOCATION ----------------
def get_location(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()
        if data.get("status") == "success":
            return f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
        else:
            return "Unknown"
    except:
        return "Unknown"

# ---------------- DEVICE FINGERPRINT ----------------
def get_device_fingerprint(request):
    user_agent = request.headers.get('User-Agent', '')
    accept_lang = request.headers.get('Accept-Language', '')
    fingerprint_raw = f"{user_agent}{accept_lang}"
    fingerprint = hashlib.md5(fingerprint_raw.encode()).hexdigest()[:12]

    # Simplify device info for display
    device = "Unknown"
    if "Windows" in user_agent:
        device = "Windows"
    elif "Mac" in user_agent:
        device = "Mac"
    elif "Linux" in user_agent:
        device = "Linux"
    elif "Android" in user_agent:
        device = "Android"
    elif "iPhone" in user_agent:
        device = "iPhone"

    browser = "Unknown"
    if "Chrome" in user_agent and "Edg" not in user_agent:
        browser = "Chrome"
    elif "Firefox" in user_agent:
        browser = "Firefox"
    elif "Safari" in user_agent and "Chrome" not in user_agent:
        browser = "Safari"
    elif "Edg" in user_agent:
        browser = "Edge"

    return f"{device} / {browser}", fingerprint

# ---------------- LOGIN TIME ANOMALY ----------------
def check_time_anomaly(username, current_hour):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Get last 10 login hours for this user
    cursor.execute("SELECT hour FROM login_history WHERE username=? ORDER BY id DESC LIMIT 10", (username,))
    rows = cursor.fetchall()
    conn.close()

    if len(rows) < 3:
        return False  # Not enough history

    hours = [r[0] for r in rows]
    avg_hour = sum(hours) / len(hours)

    # If current hour is more than 6 hours away from average = anomaly
    diff = abs(current_hour - avg_hour)
    if diff > 12:
        diff = 24 - diff  # Handle midnight wraparound

    return diff > 6

# ---------------- CONCURRENT SESSION CHECK ----------------
def check_concurrent_session(username, new_session_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT session_id FROM active_sessions WHERE username=?", (username,))
    row = cursor.fetchone()

    if row and row[0] != new_session_id:
        # Another session exists — force it out
        cursor.execute("REPLACE INTO active_sessions (username, session_id, timestamp) VALUES (?, ?, ?)",
                       (username, new_session_id, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
        return True  # Concurrent session detected

    cursor.execute("REPLACE INTO active_sessions (username, session_id, timestamp) VALUES (?, ?, ?)",
                   (username, new_session_id, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    return False

# ---------------- DATABASE INIT ----------------
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user',
            failed_attempts INTEGER DEFAULT 0,
            lock_until TEXT,
            is_banned INTEGER DEFAULT 0
        )
    """)

    try:
        cursor.execute("ALTER TABLE users ADD COLUMN is_banned INTEGER DEFAULT 0")
    except:
        pass

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            risk_level TEXT,
            status TEXT,
            timestamp TEXT,
            location TEXT DEFAULT 'Unknown',
            device_info TEXT DEFAULT 'Unknown'
        )
    """)

    try:
        cursor.execute("ALTER TABLE login_logs ADD COLUMN device_info TEXT DEFAULT 'Unknown'")
    except:
        pass

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            failed_attempts INTEGER DEFAULT 0,
            lock_until TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            hour INTEGER,
            timestamp TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS active_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            session_id TEXT,
            timestamp TEXT
        )
    """)

    conn.commit()
    conn.close()


# ---------------- HOME ----------------
@app.route('/')
def home():
    return redirect('/login')


# ---------------- REGISTER ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':

        # 🍯 HONEYPOT CHECK
        honeypot = request.form.get('website', '')
        if honeypot:
            return render_template('message.html', msg_type="blocked",
                                   message="Bot detected! Access denied.")

        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
        except:
            conn.close()
            return render_template('message.html', msg_type="error", message="User already exists! Please choose a different username.")
        conn.close()
        return redirect('/login')

    return render_template('register.html')


# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        # 🍯 HONEYPOT CHECK
        honeypot = request.form.get('website', '')
        if honeypot:
            return render_template('message.html', msg_type="blocked",
                                   message="Bot detected! Access denied.")

        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr
        location = get_location(ip_address)

        # 🖥️ DEVICE FINGERPRINT
        device_info, fingerprint = get_device_fingerprint(request)

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # -------- IP BLOCK CHECK --------
        cursor.execute("SELECT failed_attempts, lock_until FROM ip_blocks WHERE ip_address=?", (ip_address,))
        ip_record = cursor.fetchone()

        if ip_record:
            ip_failed_attempts, ip_lock_until = ip_record
            if ip_lock_until:
                lock_time = datetime.datetime.strptime(ip_lock_until, "%Y-%m-%d %H:%M:%S")
                if datetime.datetime.now() < lock_time:
                    conn.close()
                    return render_template('message.html', msg_type="blocked",
                                           message=f"Your IP has been blocked. Try again after {ip_lock_until}.")
        else:
            ip_failed_attempts = 0

        # -------- USER FETCH --------
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cursor.fetchone()

        if not user:
            conn.close()
            return render_template('message.html', msg_type="error", message="User not found! Please check your username or register.")

        stored_password = user[2]
        failed_attempts = user[4]
        lock_until = user[5]
        is_banned = user[6] if len(user) > 6 else 0

        if is_banned:
            conn.close()
            return render_template('message.html', msg_type="blocked",
                                   message="Your account has been banned. Please contact support.")

        if lock_until:
            lock_time = datetime.datetime.strptime(lock_until, "%Y-%m-%d %H:%M:%S")
            if datetime.datetime.now() < lock_time:
                conn.close()
                return render_template('message.html', msg_type="blocked",
                                       message=f"Account locked. Try again after {lock_until}.")

        # -------- WRONG PASSWORD --------
        if not check_password_hash(stored_password, password):
            failed_attempts += 1
            ip_failed_attempts += 1
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            cursor.execute("UPDATE users SET failed_attempts=? WHERE username=?", (failed_attempts, username))
            if ip_record:
                cursor.execute("UPDATE ip_blocks SET failed_attempts=? WHERE ip_address=?", (ip_failed_attempts, ip_address))
            else:
                cursor.execute("INSERT INTO ip_blocks (ip_address, failed_attempts) VALUES (?, ?)", (ip_address, ip_failed_attempts))

            if ip_failed_attempts >= 10:
                lock_time = datetime.datetime.now() + datetime.timedelta(minutes=10)
                lock_until_ip = lock_time.strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("UPDATE ip_blocks SET lock_until=? WHERE ip_address=?", (lock_until_ip, ip_address))

            cursor.execute(
                "INSERT INTO login_logs (username, risk_level, status, timestamp, location, device_info) VALUES (?, ?, ?, ?, ?, ?)",
                (username, "Low", "Wrong Password", timestamp, location, device_info)
            )
            conn.commit()
            conn.close()
            return render_template('message.html', msg_type="error",
                                   message=f"Wrong password! {max(0, 5 - failed_attempts)} attempts remaining.")

        # -------- PASSWORD CORRECT — RISK SCORING --------
        current_hour = datetime.datetime.now().hour
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        risk = "Low"
        risk_reasons = []

        if failed_attempts >= 5:
            risk = "High"
            risk_reasons.append("Too many failed attempts")
        elif failed_attempts >= 3:
            risk = "Medium"
            risk_reasons.append("Multiple failed attempts")

        # ⏰ TIME ANOMALY CHECK
        if check_time_anomaly(username, current_hour):
            risk = "Medium" if risk == "Low" else risk
            risk_reasons.append("Unusual login time detected")

        # Nighttime check
        if 0 <= current_hour <= 5 and risk == "Low":
            risk = "Medium"
            risk_reasons.append("Late night login")

        # Save login hour to history
        cursor.execute("INSERT INTO login_history (username, hour, timestamp) VALUES (?, ?, ?)",
                       (username, current_hour, timestamp))

        # HIGH RISK → LOCK
        if risk == "High":
            lock_time = datetime.datetime.now() + datetime.timedelta(minutes=5)
            lock_until_user = lock_time.strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("UPDATE users SET lock_until=? WHERE username=?", (lock_until_user, username))
            cursor.execute(
                "INSERT INTO login_logs (username, risk_level, status, timestamp, location, device_info) VALUES (?, ?, ?, ?, ?, ?)",
                (username, "High", "Account Locked", timestamp, location, device_info)
            )
            conn.commit()
            conn.close()
            return render_template('message.html', msg_type="blocked",
                                   message=f"High risk detected! Account locked until {lock_until_user}. Reason: {', '.join(risk_reasons)}")

        # MEDIUM RISK → OTP
        if risk == "Medium":
            cursor.execute(
                "INSERT INTO login_logs (username, risk_level, status, timestamp, location, device_info) VALUES (?, ?, ?, ?, ?, ?)",
                (username, "Medium", "OTP Required", timestamp, location, device_info)
            )
            conn.commit()

            otp = str(random.randint(100000, 999999))
            session['otp'] = otp
            session['otp_expiry'] = time.time() + 300
            session['temp_user'] = username
            print(f"\n🔐 OTP for {username}: {otp}\n")
            print(f"⚠️  Risk Reasons: {', '.join(risk_reasons)}\n")
            conn.close()
            return redirect('/verify-otp')

        # LOW RISK → LOGIN
        cursor.execute("UPDATE users SET failed_attempts=0, lock_until=NULL WHERE username=?", (username,))
        cursor.execute(
            "INSERT INTO login_logs (username, risk_level, status, timestamp, location, device_info) VALUES (?, ?, ?, ?, ?, ?)",
            (username, "Low", "Success", timestamp, location, device_info)
        )
        conn.commit()
        conn.close()

        # 👥 CONCURRENT SESSION CHECK
        new_session_id = str(uuid.uuid4())
        session.permanent = True
        session['username'] = username
        session['session_id'] = new_session_id
        session['ip'] = ip_address
        session['ua'] = request.headers.get('User-Agent', '')

        concurrent = check_concurrent_session(username, new_session_id)
        if concurrent:
            print(f"\n⚠️  Concurrent session detected for {username} — previous session terminated!\n")

        return redirect('/dashboard')

    return render_template('login.html')


# ---------------- SESSION GUARD ----------------
def session_guard():
    if 'username' not in session:
        return False
    # Verify IP and User Agent haven't changed (session hijacking protection)
    if session.get('ip') and session['ip'] != request.remote_addr:
        session.clear()
        return False
    return True


# ---------------- OTP VERIFY ----------------
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp' not in session:
        return redirect('/login')

    if request.method == 'POST':
        entered_otp = request.form['otp']

        if time.time() > session.get('otp_expiry', 0):
            session.pop('otp', None)
            session.pop('otp_expiry', None)
            session.pop('temp_user', None)
            return render_template('message.html', msg_type="otp_error", message="OTP expired! Please login again.")

        if entered_otp == session['otp']:
            username = session['temp_user']
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET failed_attempts=0 WHERE username=?", (username,))
            conn.commit()
            conn.close()

            session.pop('otp', None)
            session.pop('otp_expiry', None)
            session.pop('temp_user', None)

            new_session_id = str(uuid.uuid4())
            session.permanent = True
            session['username'] = username
            session['session_id'] = new_session_id
            session['ip'] = request.remote_addr
            session['ua'] = request.headers.get('User-Agent', '')

            check_concurrent_session(username, new_session_id)
            return redirect('/dashboard')
        else:
            return render_template('message.html', msg_type="otp_error", message="Invalid OTP! Please try again.")

    return render_template('verify_otp.html')


# ---------------- DASHBOARD ROUTER ----------------
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')
    session.permanent = True
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username=?", (session['username'],))
    row = cursor.fetchone()
    conn.close()
    if row and row[0] == 'admin':
        return redirect('/admin')
    else:
        return redirect('/portal')


# ---------------- ADMIN PANEL ----------------
@app.route('/admin')
def admin_panel():
    if 'username' not in session:
        return redirect('/login')

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT role FROM users WHERE username=?", (session['username'],))
    role = cursor.fetchone()[0]
    if role != 'admin':
        conn.close()
        return render_template('message.html', msg_type="error", message="Access Denied! Admin only.")

    cursor.execute("SELECT username, risk_level, status, timestamp, location, device_info FROM login_logs ORDER BY id DESC LIMIT 20")
    logs = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM login_logs")
    total_logins = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM login_logs WHERE status='Wrong Password'")
    total_failures = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ip_blocks WHERE lock_until IS NOT NULL")
    active_ip_blocks = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM users WHERE is_banned=1")
    total_banned = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM login_logs WHERE risk_level='Low'")
    low_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM login_logs WHERE risk_level='Medium'")
    medium_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM login_logs WHERE risk_level='High'")
    high_count = cursor.fetchone()[0]

    labels = []
    daily_counts = []
    for i in range(6, -1, -1):
        day = (datetime.datetime.now() - datetime.timedelta(days=i)).strftime("%Y-%m-%d")
        label = (datetime.datetime.now() - datetime.timedelta(days=i)).strftime("%d %b")
        cursor.execute("SELECT COUNT(*) FROM login_logs WHERE timestamp LIKE ?", (f"{day}%",))
        count = cursor.fetchone()[0]
        labels.append(label)
        daily_counts.append(count)

    cursor.execute("SELECT ip_address, failed_attempts, lock_until FROM ip_blocks WHERE lock_until IS NOT NULL ORDER BY id DESC")
    blocked_ips = cursor.fetchall()

    cursor.execute("SELECT id, username, role, failed_attempts, lock_until, is_banned FROM users ORDER BY id DESC")
    all_users = cursor.fetchall()

    cursor.execute("SELECT username, status, timestamp, location FROM login_logs WHERE risk_level='High' ORDER BY id DESC LIMIT 5")
    alerts = cursor.fetchall()

    conn.close()

    return render_template('admin.html',
        user=session['username'],
        logs=logs,
        total_logins=total_logins,
        total_failures=total_failures,
        active_ip_blocks=active_ip_blocks,
        total_banned=total_banned,
        low_count=low_count,
        medium_count=medium_count,
        high_count=high_count,
        chart_labels=labels,
        daily_counts=daily_counts,
        blocked_ips=blocked_ips,
        all_users=all_users,
        alerts=alerts
    )


# ---------------- USER PORTAL ----------------
@app.route('/portal')
def user_portal():
    if 'username' not in session:
        return redirect('/login')

    session.permanent = True
    username = session['username']

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT role FROM users WHERE username=?", (username,))
    role = cursor.fetchone()[0]
    if role == 'admin':
        conn.close()
        return redirect('/admin')

    cursor.execute("SELECT username, risk_level, status, timestamp, location, device_info FROM login_logs WHERE username=? ORDER BY id DESC LIMIT 10", (username,))
    logs = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM login_logs WHERE username=?", (username,))
    total_logins = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM login_logs WHERE username=? AND status='Wrong Password'", (username,))
    total_failures = cursor.fetchone()[0]
    cursor.execute("SELECT failed_attempts, lock_until FROM users WHERE username=?", (username,))
    user_info = cursor.fetchone()
    conn.close()

    return render_template('user_portal.html',
        user=username,
        logs=logs,
        total_logins=total_logins,
        total_failures=total_failures,
        failed_attempts=user_info[0],
        lock_until=user_info[1]
    )


# ---------------- BAN / UNBAN ----------------
@app.route('/admin/ban/<int:user_id>')
def ban_user(user_id):
    if 'username' not in session:
        return redirect('/login')
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username=?", (session['username'],))
    role = cursor.fetchone()[0]
    if role != 'admin':
        conn.close()
        return render_template('message.html', msg_type="error", message="Access Denied!")
    cursor.execute("UPDATE users SET is_banned=1 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return redirect('/admin')


@app.route('/admin/unban/<int:user_id>')
def unban_user(user_id):
    if 'username' not in session:
        return redirect('/login')
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username=?", (session['username'],))
    role = cursor.fetchone()[0]
    if role != 'admin':
        conn.close()
        return render_template('message.html', msg_type="error", message="Access Denied!")
    cursor.execute("UPDATE users SET is_banned=0, failed_attempts=0, lock_until=NULL WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return redirect('/admin')


# ---------------- UNBLOCK IP ----------------
@app.route('/admin/unblock/<ip>')
def unblock_ip(ip):
    if 'username' not in session:
        return redirect('/login')
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username=?", (session['username'],))
    role = cursor.fetchone()[0]
    if role != 'admin':
        conn.close()
        return render_template('message.html', msg_type="error", message="Access Denied!")
    cursor.execute("UPDATE ip_blocks SET lock_until=NULL, failed_attempts=0 WHERE ip_address=?", (ip,))
    conn.commit()
    conn.close()
    return redirect('/admin')


# ---------------- CHANGE PASSWORD ----------------
@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect('/login')

    if request.method == 'POST':
        step = request.form.get('step')

        if step == 'request_otp':
            otp = str(random.randint(100000, 999999))
            session['pwd_otp'] = otp
            session['pwd_otp_expiry'] = time.time() + 300
            print(f"\n🔐 Password Change OTP for {session['username']}: {otp}\n")
            return render_template('change_password.html', step='verify_otp')

        elif step == 'verify_otp':
            entered_otp = request.form.get('otp')
            if time.time() > session.get('pwd_otp_expiry', 0):
                session.pop('pwd_otp', None)
                return render_template('message.html', msg_type="otp_error", message="OTP expired! Please try again.")
            if entered_otp != session.get('pwd_otp'):
                return render_template('message.html', msg_type="otp_error", message="Invalid OTP!")
            session.pop('pwd_otp', None)
            return render_template('change_password.html', step='new_password')

        elif step == 'new_password':
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            if new_password != confirm_password:
                return render_template('message.html', msg_type="error", message="Passwords do not match!")
            hashed = generate_password_hash(new_password)
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password=? WHERE username=?", (hashed, session['username']))
            conn.commit()
            conn.close()
            return render_template('message.html', msg_type="success", message="Password changed successfully! Please login again.")

    return render_template('change_password.html', step='request_otp')


# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    username = session.get('username')
    if username:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM active_sessions WHERE username=?", (username,))
        conn.commit()
        conn.close()
    session.clear()
    return redirect('/login')


# ---------------- RUN ----------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)