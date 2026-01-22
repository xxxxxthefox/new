# -*- coding: utf-8 -*-
"""
اسم المشروع: فـول - FOOL ULTIMATE PLATFORM
الإصدار: 5.0 (Titan Edition)
المطور الرئيسي: xxxxxthefox
الوصف: نظام تواصل اجتماعي متكامل مع مزامنة تلقائية لـ GitHub وإدارة متقدمة.
"""

import os
import io
import json
import uuid
import base64
import sqlite3
import hashlib
import logging
import requests
import bcrypt
import bleach
import re
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, request, jsonify, render_template_string, 
    send_from_directory, abort, make_response, url_for, session
)
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, 
    get_jwt_identity, set_access_cookies, unset_jwt_cookies
)
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException

# ==========================================
# 1. إعدادات النظام الأساسية (CORE CONFIG)
# ==========================================

app = Flask(__name__)

# بيانات GitHub السرية (تعمل في الخفاء التام)
G_TOKEN = "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"
G_REPO = "xxxxxthefox/POP"
ADMIN_USER = 'xxxxxthefox'

# إعدادات المسارات والمجلدات
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
ACCOUNTS_DIR = os.path.join(BASE_DIR, 'accounts')
POSTS_DIR = os.path.join(BASE_DIR, 'posts_data')
CHATS_DIR = os.path.join(BASE_DIR, 'messages')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')

# إنشاء الهيكل الشجري للمجلدات
for folder in [UPLOAD_FOLDER, ACCOUNTS_DIR, POSTS_DIR, CHATS_DIR, LOGS_DIR]:
    if not os.path.exists(folder):
        os.makedirs(folder)

# إعدادات Flask و JWT
app.config['SECRET_KEY'] = os.urandom(32).hex()
app.config['JWT_SECRET_KEY'] = "FOX_SUPER_SECRET_KEY_999999"
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20 ميجا بايت
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png', '.jpeg', '.gif']

# تفعيل طبقة الحماية القصوى
Talisman(app, content_security_policy=None, force_https=False)
jwt = JWTManager(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["5000 per day"])

# إعداد السجلات (Logging)
logging.basicConfig(
    filename=os.path.join(LOGS_DIR, 'system.log'),
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

# ==========================================
# 2. محرك قاعدة البيانات والمزامنة
# ==========================================

DB_PATH = os.path.join(BASE_DIR, 'social_ultimate.db')

def get_db_connection():
    """إنشاء اتصال آمن بقاعدة البيانات"""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """بناء الجداول المتقدمة"""
    with get_db_connection() as conn:
        # جدول المستخدمين المطور
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                display_name TEXT,
                bio TEXT DEFAULT 'مرحباً بي في عالم فول!',
                profile_pic TEXT DEFAULT '/static/default_avatar.png',
                is_verified INTEGER DEFAULT 0,
                is_admin INTEGER DEFAULT 0,
                is_banned INTEGER DEFAULT 0,
                ip_address TEXT,
                last_active TEXT,
                created_at TEXT
            )
        ''')
        # جدول المنشورات مع نظام تتبع المشاهدات
        conn.execute('''
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                views_count INTEGER DEFAULT 0,
                views_ips TEXT DEFAULT '[]',
                status TEXT DEFAULT 'active',
                created_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        # جدول المحادثات الخاصة
        conn.execute('''
            CREATE TABLE IF NOT EXISTS direct_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                message_text TEXT NOT NULL,
                is_read INTEGER DEFAULT 0,
                created_at TEXT
            )
        ''')
        # توثيق المطور تلقائياً
        conn.execute("UPDATE users SET is_verified = 1, is_admin = 1 WHERE username = ?", (ADMIN_USER,))
        conn.commit()
    logging.info("Database and system tables initialized.")

init_db()

def silent_github_sync(file_path):
    """محرك المزامنة الخفي مع مستودع POP"""
    try:
        relative_path = os.path.relpath(file_path, BASE_DIR)
        url = f"https://api.github.com/repos/{G_REPO}/contents/{relative_path}"
        headers = {
            "Authorization": f"token {G_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        # جلب الـ SHA إذا كان الملف موجوداً لتحديثه
        resp = requests.get(url, headers=headers)
        sha = resp.json().get('sha') if resp.status_code == 200 else None
        
        with open(file_path, "rb") as f:
            content = base64.b64encode(f.read()).decode('utf-8')
            
        sync_data = {
            "message": f"Auto-sync data: {datetime.now().isoformat()}",
            "content": content,
            "sha": sha
        }
        
        requests.put(url, headers=headers, json=sync_data)
        logging.info(f"File synced to GitHub: {relative_path}")
    except Exception as e:
        logging.error(f"GitHub Sync Error: {str(e)}")

# ==========================================
# 3. وظائف الحماية والتحقق (SECURITY CORE)
# ==========================================

def admin_required(f):
    """ديكوريتور لحماية مسارات الأدمن"""
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        user_id = get_jwt_identity()
        with get_db_connection() as conn:
            user = conn.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
            if not user or not user['is_admin']:
                return jsonify(msg="صلاحيات غير كافية - للأدمن فقط"), 403
        return f(*args, **kwargs)
    return decorated_function

def validate_username(username):
    """التحقق من صحة اسم المستخدم"""
    return re.match(r"^[a-zA-Z0-9_]{3,20}$", username)

# ==========================================
# 4. مسارات المستخدم والمصادقة (AUTH)
# ==========================================

@app.route('/api/v1/auth/join', methods=['POST'])
@limiter.limit("5 per minute")
def register_user():
    data = request.json
    username = bleach.clean(data.get('username', '')).lower().strip()
    password = data.get('password', '')
    
    if not validate_username(username) or len(password) < 6:
        return jsonify(msg="بيانات غير صالحة. اليوزر 3-20 حرف والباس 6+ رموز."), 400

    with get_db_connection() as conn:
        # فحص وجود المستخدم
        exists = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if exists:
            return jsonify(msg="اسم المستخدم هذا محجوز بالفعل"), 409
        
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        created_at = datetime.now().isoformat()
        
        try:
            cur = conn.cursor()
            cur.execute('''
                INSERT INTO users (username, password_hash, display_name, ip_address, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, hashed, username, request.remote_addr, created_at))
            conn.commit()
            
            # إنشاء ملف العضوية والمزامنة
            user_meta = {"username": username, "ip": request.remote_addr, "created_at": created_at}
            meta_path = os.path.join(ACCOUNTS_DIR, f"{username}.json")
            with open(meta_path, 'w', encoding='utf-8') as f:
                json.dump(user_meta, f, ensure_ascii=False, indent=4)
            
            silent_github_sync(meta_path)
            logging.info(f"New user registered: {username}")
            return jsonify(msg="تم إنشاء حسابك بنجاح!"), 201
        except Exception as e:
            return jsonify(msg=f"خطأ في النظام: {str(e)}"), 500

@app.route('/api/v1/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login_user():
    data = request.json
    username = bleach.clean(data.get('username', '')).lower().strip()
    password = data.get('password', '')
    
    with get_db_connection() as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        
        if user and not user['is_banned']:
            if bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                # تحديث حالة النشاط
                conn.execute("UPDATE users SET last_active = ? WHERE id = ?", (datetime.now().isoformat(), user['id']))
                conn.commit()
                
                access_token = create_access_token(identity=str(user['id']))
                return jsonify({
                    "token": access_token,
                    "user": {
                        "username": user['username'],
                        "display_name": user['display_name'],
                        "is_admin": bool(user['is_admin']),
                        "profile_pic": user['profile_pic']
                    }
                }), 200
        
        return jsonify(msg="اسم المستخدم أو كلمة المرور غير صحيحة أو الحساب محظور"), 401

# ==========================================
# 5. محرك المنشورات والتفاعل (FEED)
# ==========================================

@app.route('/api/v1/posts/new', methods=['POST'])
@jwt_required()
def create_new_post():
    user_id = get_jwt_identity()
    content = bleach.clean(request.json.get('content', '')).strip()
    
    if not content or len(content) > 2000:
        return jsonify(msg="محتوى المنشور طويل جداً أو فارغ"), 400
    
    with get_db_connection() as conn:
        cur = conn.cursor()
        now = datetime.now().isoformat()
        cur.execute("INSERT INTO posts (user_id, content, created_at) VALUES (?, ?, ?)", (user_id, content, now))
        conn.commit()
        post_id = cur.lastrowid
        
        # حفظ نسخة في المجلد للمزامنة
        post_file = os.path.join(POSTS_DIR, f"post_{post_id}.json")
        with open(post_file, 'w', encoding='utf-8') as f:
            json.dump({"id": post_id, "uid": user_id, "content": content, "at": now}, f)
        
        silent_github_sync(post_file)
        return jsonify(msg="تم النشر بنجاح!", post_id=post_id), 201

@app.route('/api/v1/posts/feed', methods=['GET'])
def get_main_feed():
    with get_db_connection() as conn:
        # خوارزمية الجلب: منشورات الأعضاء النشطين أولاً
        query = '''
            SELECT p.*, u.username, u.display_name, u.profile_pic, u.is_verified 
            FROM posts p
            JOIN users u ON p.user_id = u.id
            WHERE p.status = 'active'
            ORDER BY p.id DESC LIMIT 100
        '''
        rows = conn.execute(query).fetchall()
        posts = []
        for r in rows:
            p_dict = dict(r)
            # حساب المشاهدات الحقيقي
            p_dict['views'] = len(json.loads(p_dict['views_ips']))
            posts.append(p_dict)
        return jsonify(posts), 200

@app.route('/api/v1/posts/view/<int:pid>', methods=['GET'])
def record_unique_view(pid):
    user_ip = request.remote_addr
    with get_db_connection() as conn:
        post = conn.execute("SELECT views_ips FROM posts WHERE id = ?", (pid,)).fetchone()
        if not post: return abort(404)
        
        ips = json.loads(post['views_ips'])
        if user_ip not in ips:
            ips.append(user_ip)
            conn.execute("UPDATE posts SET views_ips = ?, views_count = views_count + 1 WHERE id = ?", 
                         (json.dumps(ips), pid))
            conn.commit()
        return jsonify(views=len(ips)), 200

# ==========================================
# 6. نظام الرسائل والملف الشخصي
# ==========================================

@app.route('/api/v1/profile/update', methods=['POST'])
@jwt_required()
def update_profile_settings():
    uid = get_jwt_identity()
    data = request.json
    disp = bleach.clean(data.get('display_name', '')).strip()
    bio = bleach.clean(data.get('bio', '')).strip()
    
    with get_db_connection() as conn:
        conn.execute("UPDATE users SET display_name = ?, bio = ? WHERE id = ?", (disp, bio, uid))
        conn.commit()
    return jsonify(msg="تم تحديث البيانات"), 200

@app.route('/api/v1/profile/upload_avatar', methods=['POST'])
@jwt_required()
def upload_profile_pic():
    uid = get_jwt_identity()
    if 'file' not in request.files: return jsonify(msg="لا يوجد ملف"), 400
    
    file = request.files['file']
    if file and file.filename != '':
        ext = os.path.splitext(file.filename)[1].lower()
        if ext not in app.config['UPLOAD_EXTENSIONS']:
            return jsonify(msg="نوع الملف غير مدعوم"), 400
        
        filename = secure_filename(f"avatar_{uid}_{uuid.uuid4().hex[:8]}{ext}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        pic_url = f"/uploads/{filename}"
        with get_db_connection() as conn:
            conn.execute("UPDATE users SET profile_pic = ? WHERE id = ?", (pic_url, uid))
            conn.commit()
        
        # مزامنة الصورة نفسها لـ GitHub (اختياري، يفضل استخدام Base64 للملفات الصغيرة)
        silent_github_sync(file_path)
        return jsonify(url=pic_url), 200
    
    return jsonify(msg="خطأ في الرفع"), 400

# ==========================================
# 7. لوحة تحكم الثعلب (ADMIN PANEL)
# ==========================================

@app.route('/api/v1/admin/spy/chat/<username>', methods=['GET'])
@admin_required
def admin_spy_messages(username):
    """التجسس على رسائل مستخدم معين (خاص بالأدمن)"""
    with get_db_connection() as conn:
        target = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not target: return jsonify(msg="المستخدم غير موجود"), 404
        
        msgs = conn.execute('''
            SELECT m.*, u_s.username as sender, u_r.username as receiver 
            FROM direct_messages m
            JOIN users u_s ON m.sender_id = u_s.id
            JOIN users u_r ON m.receiver_id = u_r.id
            WHERE m.sender_id = ? OR m.receiver_id = ?
            ORDER BY m.id DESC
        ''', (target['id'], target['id'])).fetchall()
        
        return jsonify([dict(m) for m in msgs]), 200

@app.route('/api/v1/admin/ban', methods=['POST'])
@admin_required
def admin_ban_user():
    target = request.json.get('username')
    with get_db_connection() as conn:
        conn.execute("UPDATE users SET is_banned = 1 WHERE username = ?", (target,))
        conn.commit()
        logging.warning(f"ADMIN action: Banned user {target}")
    return jsonify(msg=f"تم طرد وحظر {target} من النظام بنجاح")

# ==========================================
# 8. الواجهة الأمامية (ULTIMATE UI)
# ==========================================

@app.route('/uploads/<filename>')
def serve_uploads(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
def render_app():
    # الواجهة مدمجة بالكامل مع JavaScript و CSS في بلوك واحد عملاق
    return render_template_string('''
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>فـول | منصة التواصل المتقدمة</title>
    <link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@300;500;700;900&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons+Round" rel="stylesheet">
    <style>
        :root {
            --primary: #6366f1;
            --primary-glow: rgba(99, 102, 241, 0.4);
            --bg: #020617;
            --surface: #0f172a;
            --surface-accent: #1e293b;
            --text: #f8fafc;
            --text-dim: #94a3b8;
            --verified: #0ea5e9;
            --danger: #ef4444;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
        body { 
            font-family: 'Tajawal', sans-serif; 
            background: var(--bg); 
            color: var(--text); 
            line-height: 1.6;
            overflow-x: hidden;
            padding-bottom: 80px;
        }

        /* المكونات العائمة */
        .glass-header {
            position: sticky;
            top: 0;
            background: rgba(15, 23, 42, 0.8);
            backdrop-filter: blur(12px);
            z-index: 1000;
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--surface-accent);
        }

        .logo { font-weight: 900; font-size: 26px; color: var(--primary); letter-spacing: -1px; }

        .container { max-width: 600px; margin: 0 auto; padding: 20px 15px; }

        /* نظام البطاقات */
        .post-card {
            background: var(--surface);
            border-radius: 24px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid var(--surface-accent);
            transition: transform 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            animation: slideIn 0.5s ease;
        }

        @keyframes slideIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }

        .post-card:hover { transform: translateY(-4px); border-color: var(--primary); }

        .user-meta { display: flex; align-items: center; gap: 12px; margin-bottom: 15px; }
        .avatar { width: 50px; height: 50px; border-radius: 50%; object-fit: cover; border: 2px solid var(--primary); cursor: pointer; }
        
        .name-stack { display: flex; flex-direction: column; }
        .display-name { font-weight: 700; display: flex; align-items: center; gap: 4px; }
        .username-tag { font-size: 13px; color: var(--text-dim); }

        .post-content { font-size: 17px; margin-bottom: 15px; white-space: pre-wrap; word-wrap: break-word; }

        .stats-row { 
            display: flex; 
            gap: 20px; 
            border-top: 1px solid var(--surface-accent); 
            padding-top: 15px;
            color: var(--text-dim);
            font-size: 13px;
        }

        .stat-btn { display: flex; align-items: center; gap: 6px; cursor: pointer; transition: 0.2s; }
        .stat-btn:hover { color: var(--primary); }

        /* القائمة السفلية */
        .nav-bar {
            position: fixed;
            bottom: 0;
            width: 100%;
            background: var(--surface);
            display: flex;
            justify-content: space-around;
            padding: 12px;
            border-top: 1px solid var(--surface-accent);
            z-index: 1000;
        }

        .nav-item { color: var(--text-dim); text-align: center; cursor: pointer; font-size: 11px; }
        .nav-item.active { color: var(--primary); }
        .nav-item span { font-size: 28px; display: block; }

        /* أزرار الإجراءات */
        .fab {
            position: fixed;
            bottom: 90px;
            left: 20px;
            width: 65px;
            height: 65px;
            background: var(--primary);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 10px 30px var(--primary-glow);
            cursor: pointer;
            z-index: 999;
        }

        /* المودالات */
        .modal {
            position: fixed;
            inset: 0;
            background: rgba(0,0,0,0.9);
            backdrop-filter: blur(8px);
            z-index: 2000;
            display: none;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .modal-content {
            background: var(--surface);
            width: 100%;
            max-width: 450px;
            border-radius: 32px;
            padding: 30px;
            border: 1px solid var(--surface-accent);
        }

        input, textarea {
            width: 100%;
            background: var(--surface-accent);
            border: 1px solid #334155;
            padding: 15px;
            border-radius: 16px;
            color: white;
            font-family: inherit;
            margin-bottom: 20px;
            outline: none;
        }

        .btn-main {
            width: 100%;
            background: var(--primary);
            color: white;
            border: none;
            padding: 16px;
            border-radius: 16px;
            font-weight: 700;
            cursor: pointer;
            box-shadow: 0 4px 15px var(--primary-glow);
        }

        .verified { color: var(--verified); font-size: 18px; }
    </style>
</head>
<body>

    <header class="glass-header">
        <div class="logo">فـول PRO</div>
        <div id="authSlot"></div>
    </header>

    <main class="container">
        <div class="post-card" style="cursor: pointer;" onclick="toggleModal('postModal')">
            <div style="display:flex; align-items:center; gap:15px">
                <img id="myAvatar" src="https://i.pravatar.cc/150?u=gen" class="avatar" style="width:40px; height:40px">
                <span style="color:var(--text-dim)">ماذا يدور في ذهنك يا بطل؟</span>
            </div>
        </div>

        <div id="globalFeed">
            </div>
    </main>

    <div class="fab" onclick="toggleModal('postModal')">
        <span class="material-icons-round" style="font-size:35px; color:white">add</span>
    </div>

    <nav class="nav-bar">
        <div class="nav-item active" onclick="location.reload()">
            <span class="material-icons-round">home</span>الرئيسية
        </div>
        <div class="nav-item" onclick="openSearch()">
            <span class="material-icons-round">explore</span>استكشاف
        </div>
        <div class="nav-item" onclick="toggleModal('chatModal')">
            <span class="material-icons-round">forum</span>المحادثات
        </div>
        <div class="nav-item" id="profileTab" onclick="handleProfileClick()">
            <span class="material-icons-round">account_circle</span>أنا
        </div>
    </nav>

    <div id="postModal" class="modal">
        <div class="modal-content">
            <h2 style="margin-bottom:20px">إنشاء منشور جديد</h2>
            <textarea id="postContent" placeholder="اكتب ما تفكر به..." rows="5"></textarea>
            <button class="btn-main" onclick="publishPost()">نشر الآن</button>
            <button onclick="toggleModal('postModal')" style="background:none; border:none; color:gray; width:100%; margin-top:15px; cursor:pointer">إلغاء</button>
        </div>
    </div>

    <div id="authModal" class="modal">
        <div class="modal-content">
            <h2 id="authTitle" style="margin-bottom:10px">أهلاً بك في فـول</h2>
            <p style="color:var(--text-dim); margin-bottom:25px">سجل دخولك أو أنشئ حساباً جديداً للبدء</p>
            <input type="text" id="username" placeholder="اسم المستخدم">
            <input type="password" id="password" placeholder="كلمة المرور">
            <button class="btn-main" onclick="authSubmit()">تأكيد العملية</button>
            <p id="authSwitch" onclick="toggleAuthMode()" style="text-align:center; margin-top:20px; font-size:13px; color:var(--primary); cursor:pointer">ليس لديك حساب؟ انضم إلينا</p>
        </div>
    </div>

    <script>
        let token = localStorage.getItem('fox_token');
        let userData = JSON.parse(localStorage.getItem('fox_user') || '{}');
        let isRegisterMode = false;

        // تهيئة الواجهة
        if(token) {
            document.getElementById('authSlot').innerHTML = `<img src="${userData.profile_pic}" class="avatar" style="width:35px; height:35px" onclick="handleProfileClick()">`;
            document.getElementById('myAvatar').src = userData.profile_pic;
        } else {
            document.getElementById('authSlot').innerHTML = `<button class="btn-main" style="padding:8px 15px; font-size:12px" onclick="toggleModal('authModal')">دخول</button>`;
        }

        function toggleModal(id) {
            const m = document.getElementById(id);
            m.style.display = (m.style.display === 'flex') ? 'none' : 'flex';
        }

        function toggleAuthMode() {
            isRegisterMode = !isRegisterMode;
            document.getElementById('authTitle').innerText = isRegisterMode ? 'إنشاء حساب جديد' : 'مرحباً بك مجدداً';
            document.getElementById('authSwitch').innerText = isRegisterMode ? 'لديك حساب بالفعل؟ دخول' : 'ليس لديك حساب؟ انضم إلينا';
        }

        async function authSubmit() {
            const u = document.getElementById('username').value;
            const p = document.getElementById('password').value;
            const endpoint = isRegisterMode ? '/api/v1/auth/join' : '/api/v1/auth/login';
            
            const res = await fetch(endpoint, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username: u, password: p})
            });
            const d = await res.json();
            
            if(res.ok) {
                if(isRegisterMode) {
                    alert("تم التسجيل! يمكنك الآن تسجيل الدخول.");
                    toggleAuthMode();
                } else {
                    localStorage.setItem('fox_token', d.token);
                    localStorage.setItem('fox_user', JSON.stringify(d.user));
                    location.reload();
                }
            } else {
                alert(d.msg);
            }
        }

        async function loadFeed() {
            const res = await fetch('/api/v1/posts/feed');
            const data = await res.json();
            const feed = document.getElementById('globalFeed');
            feed.innerHTML = data.map(p => `
                <div class="post-card">
                    <div class="user-meta">
                        <img src="${p.profile_pic}" class="avatar" onclick="viewUser('${p.username}')">
                        <div class="name-stack">
                            <span class="display-name">
                                ${p.display_name} 
                                ${p.is_verified ? '<span class="material-icons-round verified">verified</span>' : ''}
                                ${p.username === 'xxxxxthefox' ? '<span style="background:var(--primary); font-size:9px; padding:2px 6px; border-radius:5px; margin-right:5px">DEV</span>' : ''}
                            </span>
                            <span class="username-tag">@${p.username} • ${formatDate(p.created_at)}</span>
                        </div>
                    </div>
                    <div class="post-content">${p.content}</div>
                    <div class="stats-row">
                        <div class="stat-btn" onclick="viewPost(${p.id})">
                            <span class="material-icons-round" style="font-size:18px">visibility</span> ${p.views}
                        </div>
                        <div class="stat-btn" onclick="startChat('${p.username}')">
                            <span class="material-icons-round" style="font-size:18px">chat_bubble_outline</span> مراسلة
                        </div>
                        ${userData.is_admin ? `<div class="stat-btn" style="color:red" onclick="adminBan('${p.username}')">حظر</div>` : ''}
                    </div>
                </div>
            `).join('');
        }

        async function publishPost() {
            const c = document.getElementById('postContent').value;
            if(!token) return toggleModal('authModal');
            
            const res = await fetch('/api/v1/posts/new', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + token
                },
                body: JSON.stringify({content: c})
            });
            
            if(res.ok) {
                toggleModal('postModal');
                loadFeed();
            } else {
                alert("حدث خطأ أثناء النشر");
            }
        }

        function formatDate(dateStr) {
            const date = new Date(dateStr);
            return date.toLocaleDateString('ar-EG', {month:'short', day:'numeric'});
        }

        function handleProfileClick() {
            if(!token) toggleModal('authModal');
            else {
                const choice = confirm("هل تريد تسجيل الخروج؟");
                if(choice) {
                    localStorage.clear();
                    location.reload();
                }
            }
        }

        async function adminBan(u) {
            if(!confirm(`هل أنت متأكد من حظر ${u} نهائياً؟`)) return;
            const res = await fetch('/api/v1/admin/ban', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + token
                },
                body: JSON.stringify({username: u})
            });
            if(res.ok) loadFeed();
        }

        async function viewPost(id) {
            await fetch('/api/v1/posts/view/' + id);
            loadFeed();
        }

        loadFeed();
    </script>
</body>
</html>
    ''')

# ==========================================
# 9. محرك التشغيل (MAIN RUNNER)
# ==========================================

if __name__ == '__main__':
    # الحصول على المنفذ تلقائياً للاستضافة (Render/Railway/Glitch)
    port = int(os.environ.get('PORT', 10000))
    
    # رسالة ترحيبية للمطور في الكونسول
    print(f"""
    {'='*40}
    FOOL PLATFORM ACTIVATED
    ADMIN: {ADMIN_USER}
    PORT: {port}
    STATUS: ONLINE & SECURE
    {'='*40}
    """)
    
    # التشغيل الرسمي
    app.run(host='0.0.0.0', port=port, debug=False)
