from flask import Flask, request, jsonify, abort
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman  # لإضافة headers أمنية (HTTPS, CSP, إلخ)
import sqlite3
import bcrypt
import os
from datetime import datetime, timedelta
import re
import requests  # للتحقق من reCAPTCHA
from collections import defaultdict
import threading
import time
from html import escape
import bleach  # لتنظيف المحتوى ضد XSS بشكل أقوى

app = Flask(__name__)

# إعدادات أمنية فائقة القوة
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', os.urandom(32).hex())  # سر عشوائي قوي تلقائيًا
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=2)  # توكن قصير العمر (ساعتين فقط)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'

jwt = JWTManager(app)

# Talisman لإضافة headers أمنية تلقائية (HSTS, CSP, X-Content-Type-Options, إلخ)
Talisman(app, content_security_policy={
    'default-src': "'self'",
    'script-src': "'self' https://www.google.com https://www.gstatic.com",
    'style-src': "'self' 'unsafe-inline'",
    'img-src': "'self' data:",
})

# Rate Limiting قوي جدًا
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["300 per day", "100 per hour"]
)

# reCAPTCHA v3 (غيّر المفاتيح إلى مفاتيحك الحقيقية من Google)
RECAPTCHA_SECRET_KEY = 'your_recaptcha_secret_key_here'  # ضروري تغييره!
RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'

# تتبع محاولات الدخول الفاشلة وحظر IP مؤقت
failed_attempts = defaultdict(lambda: {'count': 0, 'last_attempt': None, 'blocked_until': None})

def cleanup_failed_attempts():
    """تنظيف تلقائي للمحاولات القديمة كل ساعة"""
    while True:
        time.sleep(3600)
        now = datetime.now()
        keys_to_delete = [ip for ip, data in failed_attempts.items() if data['blocked_until'] and now > data['blocked_until']]
        for ip in keys_to_delete:
            del failed_attempts[ip]

threading.Thread(target=cleanup_failed_attempts, daemon=True).start()

DB_FILE = 'forum.db'

def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    if not os.path.exists(DB_FILE):
        with get_db() as conn:
            conn.execute('''
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            ''')
            conn.execute('''
                CREATE TABLE posts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    date TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            ''')
            conn.execute('CREATE INDEX idx_posts_date ON posts(date DESC)')

init_db()

# قوة كلمة المرور فائقة
def is_strong_password(password):
    if len(password) < 14:
        return False
    if not all([
        re.search(r'[A-Z]', password),
        re.search(r'[a-z]', password),
        re.search(r'\d', password),
        re.search(r'[!@#$%^&*(),.?":{}|<>]', password)
    ]):
        return False
    return True

# التحقق من reCAPTCHA
def verify_recaptcha(token):
    if not token:
        return False
    try:
        response = requests.post(RECAPTCHA_VERIFY_URL, data={
            'secret': RECAPTCHA_SECRET_KEY,
            'response': token
        }, timeout=5)
        result = response.json()
        return result.get('success') and result.get('score', 1.0) > 0.5  # score > 0.5 لـ v3
    except:
        return False

@app.before_request
def block_ip_if_needed():
    ip = get_remote_address()
    data = failed_attempts[ip]
    if data['blocked_until'] and datetime.now() < data['blocked_until']:
        abort(429, description="تم حظر IP مؤقتًا بسبب محاولات فاشلة كثيرة")

@app.route('/register', methods=['POST'])
@limiter.limit("3 per minute")  # حد صارم جدًا على التسجيل
def register():
    ip = get_remote_address()
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password')
    recaptcha_token = data.get('recaptcha_token')

    if not verify_recaptcha(recaptcha_token):
        failed_attempts[ip]['count'] += 1
        return jsonify({'error': 'فشل التحقق من CAPTCHA'}), 400

    if not username or not password:
        return jsonify({'error': 'البيانات ناقصة'}), 400

    if not (4 <= len(username) <= 20) or not re.match(r'^[\w]+$', username):
        return jsonify({'error': 'اسم مستخدم غير صالح (أحرف وأرقام فقط، 4-20)'}), 400

    if not is_strong_password(password):
        return jsonify({'error': 'كلمة المرور ضعيفة جدًا! 14+ حرف، أحرف كبيرة/صغيرة/أرقام/رموز خاصة'}), 400

    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=16))  # 16 rounds = أقوى

    try:
        with get_db() as conn:
            conn.execute('INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)',
                         (username, password_hash, datetime.now().isoformat()))
        return jsonify({'success': 'تم التسجيل بنجاح'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'اسم المستخدم موجود'}), 400

@app.route('/login', methods=['POST'])
@limiter.limit("8 per minute")
def login():
    ip = get_remote_address()
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password')
    recaptcha_token = data.get('recaptcha_token')

    if not verify_recaptcha(recaptcha_token):
        failed_attempts[ip]['count'] += 1
        return jsonify({'error': 'فشل التحقق من CAPTCHA'}), 400

    if not username or not password:
        return jsonify({'error': 'البيانات ناقصة'}), 400

    with get_db() as conn:
        user = conn.execute('SELECT id, username, password_hash FROM users WHERE username = ?', (username,)).fetchone()

    if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
        # إعادة تعيين المحاولات الفاشلة
        if ip in failed_attempts:
            del failed_attempts[ip]
        access_token = create_access_token(identity={'id': user['id'], 'username': user['username']})
        return jsonify({'token': access_token})

    # زيادة عداد المحاولات الفاشلة
    attempts = failed_attempts[ip]
    attempts['count'] += 1
    attempts['last_attempt'] = datetime.now()
    if attempts['count'] >= 5:
        attempts['blocked_until'] = datetime.now() + timedelta(hours=1)  # حظر لساعة
    return jsonify({'error': 'بيانات دخول خاطئة'}), 401

@app.route('/me', methods=['GET'])
@jwt_required()
def me():
    current_user = get_jwt_identity()
    return jsonify({'id': current_user['id'], 'username': current_user['username']})

@app.route('/posts', methods=['GET'])
def get_posts():
    page = max(1, request.args.get('page', 1, type=int))
    per_page = 20
    offset = (page - 1) * per_page
    with get_db() as conn:
        total = conn.execute('SELECT COUNT(*) FROM posts').fetchone()[0]
        posts = conn.execute('''
            SELECT p.id, p.title, p.content, p.date, u.username 
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            ORDER BY p.date DESC
            LIMIT ? OFFSET ?
        ''', (per_page, offset)).fetchall()
    return jsonify({
        'posts': [dict(post) for post in posts],
        'page': page,
        'total': total,
        'pages': (total + per_page - 1) // per_page
    })

@app.route('/post', methods=['POST'])
@jwt_required()
@limiter.limit("10 per hour")  # حد على النشر لمنع spam
def create_post():
    current_user = get_jwt_identity()
    data = request.get_json()
    title = bleach.clean(data.get('title', '').strip())
    content = bleach.clean(data.get('content', '').strip())

    if not title or not content or len(title) > 150 or len(content) > 10000:
        return jsonify({'error': 'بيانات المنشور غير صالحة'}), 400

    date = datetime.now().isoformat()
    with get_db() as conn:
        conn.execute('INSERT INTO posts (user_id, title, content, date) VALUES (?, ?, ?, ?)', 
                     (current_user['id'], title, content, date))
    return jsonify({'success': 'تم النشر بنجاح'}), 201

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)  # threaded للسرعة
