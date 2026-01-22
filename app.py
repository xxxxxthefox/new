from flask import Flask, request, jsonify, render_template_string
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import bcrypt
import os
from datetime import datetime, timedelta
import bleach
import re

app = Flask(__name__)

# --- إعدادات الحماية المتقدمة وجلسات المستخدم ---
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', os.urandom(32).hex())
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'

# Talisman لتأمين الرؤوس (Headers) والاتصال
Talisman(app, content_security_policy=None, force_https=False)

jwt = JWTManager(app)

# تحديد عدد الطلبات لحماية السيرفر من هجمات الإغراق
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

DB_FILE = 'social_ultimate.db'

def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        # جدول المستخدمين المطور
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            username TEXT UNIQUE NOT NULL, 
            password_hash TEXT NOT NULL,
            display_name TEXT, 
            bio TEXT, 
            profile_pic TEXT DEFAULT 'https://i.pravatar.cc/150?u=user'
        )''')
        # جدول المنشورات مع عداد المشاهدات
        conn.execute('''CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            user_id INTEGER NOT NULL, 
            content TEXT NOT NULL, 
            views INTEGER DEFAULT 0, 
            date TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id))''')
        # جدول التعليقات
        conn.execute('''CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            post_id INTEGER NOT NULL, 
            user_id INTEGER NOT NULL, 
            content TEXT NOT NULL, 
            date TEXT NOT NULL,
            FOREIGN KEY(post_id) REFERENCES posts(id),
            FOREIGN KEY(user_id) REFERENCES users(id))''')
    print("Database has been initialized successfully.")

init_db()

# --- مسارات الـ API (الخلفية) ---

@app.route('/auth', methods=['POST'])
@limiter.limit("10 per minute")
def auth():
    data = request.json
    username = bleach.clean(data.get('username', '')).strip().lower()
    password = data.get('password', '')
    is_register = data.get('register', False)

    if not username or len(password) < 6:
        return jsonify(msg="بيانات غير صالحة أو كلمة مرور قصيرة جداً"), 400

    with get_db() as conn:
        if is_register:
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            try:
                conn.execute("INSERT INTO users (username, password_hash, display_name) VALUES (?,?,?)", 
                             (username, password_hash, username))
                conn.commit()
                return jsonify(msg="تم إنشاء الحساب بنجاح"), 201
            except sqlite3.IntegrityError:
                return jsonify(msg="اسم المستخدم موجود بالفعل"), 409
        else:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                access_token = create_access_token(identity=str(user['id']))
                return jsonify(token=access_token, username=username), 200
            return jsonify(msg="اسم المستخدم أو كلمة المرور غير صحيحة"), 401

@app.route('/feed', methods=['GET'])
def get_feed():
    with get_db() as conn:
        posts = conn.execute('''
            SELECT p.*, u.display_name, u.username, u.profile_pic,
            (SELECT COUNT(*) FROM comments WHERE post_id = p.id) as comment_count 
            FROM posts p JOIN users u ON p.user_id = u.id 
            ORDER BY p.id DESC LIMIT 50
        ''').fetchall()
    return jsonify([dict(p) for p in posts])

@app.route('/post/<int:pid>', methods=['GET'])
def get_post_detail(pid):
    with get_db() as conn:
        # زيادة عداد المشاهدات عند زيارة الرابط
        conn.execute("UPDATE posts SET views = views + 1 WHERE id = ?", (pid,))
        conn.commit()
        
        post = conn.execute('''
            SELECT p.*, u.display_name, u.username, u.profile_pic 
            FROM posts p JOIN users u ON p.user_id = u.id 
            WHERE p.id = ?''', (pid,)).fetchone()
        
        comments = conn.execute('''
            SELECT c.*, u.display_name, u.username, u.profile_pic 
            FROM comments c JOIN users u ON c.user_id = u.id 
            WHERE c.post_id = ? ORDER BY c.id ASC''', (pid,)).fetchall()
        
        if post:
            return jsonify(post=dict(post), comments=[dict(c) for c in comments])
    return jsonify(msg="المنشور غير موجود"), 404

@app.route('/profile/me', methods=['GET'])
@jwt_required()
def get_profile():
    user_id = get_jwt_identity()
    with get_db() as conn:
        user = conn.execute("SELECT username, display_name, bio, profile_pic FROM users WHERE id = ?", (user_id,)).fetchone()
    return jsonify(dict(user))

@app.route('/profile/update', methods=['POST'])
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    data = request.json
    display_name = bleach.clean(data.get('display_name', ''))
    bio = bleach.clean(data.get('bio', ''))
    profile_pic = bleach.clean(data.get('profile_pic', ''))

    with get_db() as conn:
        conn.execute("UPDATE users SET display_name=?, bio=?, profile_pic=? WHERE id=?", 
                     (display_name, bio, profile_pic, user_id))
        conn.commit()
    return jsonify(msg="تم تحديث الملف الشخصي بنجاح")

@app.route('/post', methods=['POST'])
@jwt_required()
def create_post():
    user_id = get_jwt_identity()
    content = bleach.clean(request.json.get('content', '')).strip()
    if not content:
        return jsonify(msg="محتوى المنشور لا يمكن أن يكون فارغاً"), 400
    
    with get_db() as conn:
        conn.execute("INSERT INTO posts (user_id, content, date) VALUES (?,?,?)", 
                     (user_id, content, datetime.now().isoformat()))
        conn.commit()
    return jsonify(msg="تم نشر منشورك")

@app.route('/comment', methods=['POST'])
@jwt_required()
def add_comment():
    user_id = get_jwt_identity()
    data = request.json
    post_id = data.get('pid')
    content = bleach.clean(data.get('content', '')).strip()
    
    if not content:
        return jsonify(msg="التعليق فارغ"), 400
        
    with get_db() as conn:
        conn.execute("INSERT INTO comments (post_id, user_id, content, date) VALUES (?,?,?,?)", 
                     (post_id, user_id, content, datetime.now().isoformat()))
        conn.commit()
    return jsonify(msg="تمت إضافة التعليق")

# --- الواجهة الأمامية (HTML / JavaScript) ---

INDEX_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>فـول - FOOL SOCIAL</title>
    <link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons+Round" rel="stylesheet">
    <style>
        :root { --primary: #6366f1; --bg: #f8fafc; --card: #ffffff; --text: #0f172a; --secondary: #64748b; }
        [data-theme="dark"] { --bg: #020617; --card: #0f172a; --text: #f8fafc; --secondary: #94a3b8; }
        
        body { font-family: 'Tajawal', sans-serif; background: var(--bg); color: var(--text); margin: 0; transition: 0.3s; padding-bottom: 80px; }
        
        .header { position: fixed; top: 0; width: 100%; background: var(--card); padding: 15px 5%; display: flex; 
                  justify-content: space-between; align-items: center; box-sizing: border-box; z-index: 1000; 
                  box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-bottom: 1px solid rgba(0,0,0,0.05); }
        
        .logo { font-size: 24px; font-weight: 700; color: var(--primary); margin: 0; cursor: pointer; text-decoration: none; }
        
        .main-container { max-width: 650px; margin: 90px auto 20px; padding: 0 15px; }
        
        .card { background: var(--card); border-radius: 20px; padding: 20px; margin-bottom: 18px; 
                box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); border: 1px solid rgba(0,0,0,0.05); transition: 0.2s; }
        .card:hover { transform: translateY(-2px); box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1); }
        
        .user-meta { display: flex; align-items: center; gap: 12px; margin-bottom: 15px; }
        .user-pic { width: 48px; height: 48px; border-radius: 50%; object-fit: cover; border: 2px solid var(--primary); }
        .post-text { font-size: 18px; line-height: 1.6; margin-bottom: 15px; word-wrap: break-word; }
        .post-stats { display: flex; gap: 20px; font-size: 13px; color: var(--secondary); }
        .stat-item { display: flex; align-items: center; gap: 5px; }

        .btn { border: none; padding: 12px 25px; border-radius: 12px; font-weight: bold; cursor: pointer; 
                transition: 0.2s; display: flex; align-items: center; gap: 8px; font-family: inherit; }
        .btn-primary { background: var(--primary); color: white; box-shadow: 0 4px 10px rgba(99, 102, 241, 0.3); }
        .btn-primary:hover { opacity: 0.9; transform: scale(1.02); }

        .bottom-nav { position: fixed; bottom: 0; width: 100%; background: var(--card); display: flex; 
                      justify-content: space-around; padding: 12px 0; border-top: 1px solid rgba(0,0,0,0.05); z-index: 1000; }
        .nav-link { color: var(--secondary); text-align: center; font-size: 11px; cursor: pointer; text-decoration: none; }
        .nav-link.active { color: var(--primary); }

        /* نوافذ عرض المنشور والملف الشخصي */
        #postOverlay { display: none; position: fixed; inset: 0; background: var(--bg); z-index: 2000; overflow-y: auto; padding-top: 70px; }
        .overlay-nav { position: fixed; top: 0; width: 100%; background: var(--card); padding: 15px; z-index: 2100; border-bottom: 1px solid rgba(0,0,0,0.1); }
        
        .comment-section { margin-top: 25px; padding-top: 20px; border-top: 1px solid rgba(0,0,0,0.05); }
        .comment-card { display: flex; gap: 10px; margin-bottom: 15px; padding: 10px; background: rgba(0,0,0,0.02); border-radius: 12px; }

        .modal { display:none; position:fixed; inset:0; background:rgba(0,0,0,0.6); backdrop-filter:blur(5px); align-items:center; justify-content:center; z-index:3000; }
        .modal-body { background: var(--card); padding: 30px; border-radius: 25px; width: 90%; max-width: 400px; }
        
        input, textarea { width: 100%; padding: 14px; border-radius: 12px; border: 1px solid rgba(0,0,0,0.1); 
                          background: var(--bg); color: var(--text); outline: none; box-sizing: border-box; margin-bottom: 15px; font-family: inherit; }
    </style>
</head>
<body data-theme="light">

    <header class="header">
        <a href="/" class="logo">فـول</a>
        <div style="display:flex; gap:15px; align-items: center;">
            <span class="material-icons-round" id="themeToggle" style="cursor:pointer; color:var(--secondary)">dark_mode</span>
            <div id="authDisplay"><button class="btn btn-primary" onclick="openModal('authModal')">ابدأ مجاناً</button></div>
        </div>
    </header>

    <div class="main-container" id="feedContainer">
        <div class="card" onclick="triggerPost()" style="cursor:pointer; color:var(--secondary); text-align:center; font-weight:500;">
            ماذا يدور في ذهنك اليوم؟ انشر الآن...
        </div>
        <div id="postsList"></div>
    </div>

    <div id="postOverlay">
        <div class="overlay-nav">
            <button class="btn" onclick="exitPostView()" style="background:none; color:var(--text)">
                <span class="material-icons-round">arrow_forward</span> رجوع للرئيسية
            </button>
        </div>
        <div class="main-container" id="singlePostData"></div>
    </div>

    <nav class="bottom-nav">
        <div class="nav-link active" onclick="location.href='/'"><span class="material-icons-round">home</span><br>الرئيسية</div>
        <div class="nav-link" onclick="triggerPost()"><span class="material-icons-round" style="font-size:32px; color:var(--primary)">add_circle</span></div>
        <div class="nav-link" onclick="openProfile()"><span class="material-icons-round">account_circle</span><br>ملفي</div>
    </nav>

    <div id="authModal" class="modal">
        <div class="modal-body">
            <h2 id="modalTitle" style="margin-top:0">أهلاً بك</h2>
            <input id="auth_user" placeholder="اسم المستخدم">
            <input id="auth_pass" type="password" placeholder="كلمة المرور">
            <button class="btn btn-primary" style="width:100%; justify-content:center" onclick="submitAuth()">تأكيد الدخول</button>
            <p id="switchAuth" onclick="toggleAuthMode()" style="text-align:center; font-size:13px; cursor:pointer; color:var(--primary); margin-top:20px;">ليس لديك حساب؟ سجل الآن</p>
        </div>
    </div>

    <div id="profileModal" class="modal">
        <div class="modal-body">
            <h3>تعديل ملفك الشخصي</h3>
            <div style="text-align:center; margin-bottom:20px">
                <img id="edit_pic_preview" src="" class="user-pic" style="width:80px; height:80px;">
                <input id="edit_pic_url" placeholder="رابط صورة الملف" oninput="document.getElementById('edit_pic_preview').src=this.value">
            </div>
            <input id="edit_display_name" placeholder="الاسم المستعار">
            <textarea id="edit_bio" placeholder="نبذة عنك..." rows="3"></textarea>
            <button class="btn btn-primary" style="width:100%; justify-content:center" onclick="updateProfileData()">حفظ التعديلات</button>
            <button class="btn" style="width:100%; justify-content:center; background:none; color:var(--secondary)" onclick="closeModal('profileModal')">إلغاء</button>
        </div>
    </div>

    <script>
        let isRegisterMode = false;
        let userToken = localStorage.getItem('token');
        let currentPostID = null;

        // تهيئة الواجهة بناءً على حالة المستخدم
        if(userToken) {
            document.getElementById('authDisplay').innerHTML = `
                <button class="btn" onclick="userLogout()" style="background:#fee2e2; color:#ef4444; padding:8px 15px;">خروج</button>
            `;
        }

        // تبديل الوضع الليلي
        document.getElementById('themeToggle').onclick = () => {
            const body = document.body;
            const mode = body.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
            body.setAttribute('data-theme', mode);
            document.getElementById('themeToggle').innerText = mode === 'light' ? 'dark_mode' : 'light_mode';
        };

        function openModal(id) { document.getElementById(id).style.display = 'flex'; }
        function closeModal(id) { document.getElementById(id).style.display = 'none'; }

        function toggleAuthMode() {
            isRegisterMode = !isRegisterMode;
            document.getElementById('modalTitle').innerText = isRegisterMode ? 'إنشاء حساب جديد' : 'أهلاً بك مجدداً';
            document.getElementById('switchAuth').innerText = isRegisterMode ? 'لديك حساب بالفعل؟ سجل دخول' : 'ليس لديك حساب؟ سجل الآن';
        }

        async function submitAuth() {
            const u = document.getElementById('auth_user').value;
            const p = document.getElementById('auth_pass').value;
            const res = await fetch('/auth', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username: u, password: p, register: isRegisterMode})
            });
            const data = await res.json();
            if(res.ok) {
                if(!isRegisterMode) {
                    localStorage.setItem('token', data.token);
                    localStorage.setItem('username', data.username);
                    location.reload();
                } else {
                    alert("تم التسجيل! يمكنك الآن تسجيل الدخول.");
                    toggleAuthMode();
                }
            } else alert(data.msg);
        }

        function userLogout() {
            localStorage.clear();
            location.reload();
        }

        async function loadFeed() {
            const res = await fetch('/feed');
            const data = await res.json();
            const container = document.getElementById('postsList');
            container.innerHTML = data.map(p => `
                <div class="card" onclick="showPost(${p.id})">
                    <div class="user-meta">
                        <img src="${p.profile_pic}" class="user-pic">
                        <div>
                            <div style="font-weight:700;">${p.display_name}</div>
                            <div style="font-size:12px; color:var(--secondary)">@${p.username} • ${new Date(p.date).toLocaleDateString('ar')}</div>
                        </div>
                    </div>
                    <div class="post-text">${p.content}</div>
                    <div class="post-stats">
                        <div class="stat-item"><span class="material-icons-round" style="font-size:18px">visibility</span> ${p.views}</div>
                        <div class="stat-item"><span class="material-icons-round" style="font-size:18px">chat_bubble_outline</span> ${p.comment_count}</div>
                    </div>
                </div>
            `).join('');
        }

        async function showPost(pid) {
            currentPostID = pid;
            const res = await fetch('/post/'+pid);
            const data = await res.json();
            const p = data.post;
            
            // تحديث رابط المتصفح
            window.history.pushState({}, '', '/post/'+pid);
            document.getElementById('postOverlay').style.display = 'block';
            
            document.getElementById('singlePostData').innerHTML = `
                <div class="card">
                    <div class="user-meta">
                        <img src="${p.profile_pic}" class="user-pic">
                        <div>
                            <div style="font-weight:700;">${p.display_name}</div>
                            <div style="font-size:12px; color:var(--secondary)">@${p.username}</div>
                        </div>
                    </div>
                    <div class="post-text" style="font-size:22px;">${p.content}</div>
                    <div style="font-size:12px; color:var(--secondary)">نُشر في: ${new Date(p.date).toLocaleString('ar-EG')} • المشاهدات: ${p.views}</div>
                </div>
                
                <div class="comment-section">
                    <h4>التعليقات (${data.comments.length})</h4>
                    ${userToken ? `
                        <textarea id="commentInput" placeholder="اكتب تعليقك هنا..." rows="3"></textarea>
                        <button class="btn btn-primary" onclick="sendComment(${pid})">إرسال تعليق</button>
                    ` : '<p style="text-align:center; color:var(--secondary)">سجل دخول لتتمكن من التعليق</p>'}
                    
                    <div id="commentsList" style="margin-top:20px">
                        ${data.comments.map(c => `
                            <div class="comment-card">
                                <img src="${c.profile_pic}" style="width:30px; height:30px; border-radius:50%">
                                <div>
                                    <strong style="font-size:13px">${c.display_name}</strong>
                                    <div style="font-size:14px">${c.content}</div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        async function sendComment(pid) {
            const content = document.getElementById('commentInput').value;
            if(!content) return;
            const res = await fetch('/comment', {
                method: 'POST',
                headers: {'Authorization': 'Bearer '+userToken, 'Content-Type': 'application/json'},
                body: JSON.stringify({pid: pid, content: content})
            });
            if(res.ok) showPost(pid);
        }

        function exitPostView() {
            document.getElementById('postOverlay').style.display = 'none';
            window.history.pushState({}, '', '/');
            loadFeed();
        }

        async function openProfile() {
            if(!userToken) return openModal('authModal');
            const res = await fetch('/profile/me', { headers: {'Authorization': 'Bearer '+userToken} });
            const d = await res.json();
            document.getElementById('edit_display_name').value = d.display_name;
            document.getElementById('edit_bio').value = d.bio || '';
            document.getElementById('edit_pic_url').value = d.profile_pic;
            document.getElementById('edit_pic_preview').src = d.profile_pic;
            openModal('profileModal');
        }

        async function updateProfileData() {
            await fetch('/profile/update', {
                method: 'POST',
                headers: {'Authorization': 'Bearer '+userToken, 'Content-Type': 'application/json'},
                body: JSON.stringify({
                    display_name: document.getElementById('edit_display_name').value,
                    bio: document.getElementById('edit_bio').value,
                    profile_pic: document.getElementById('edit_pic_url').value
                })
            });
            location.reload();
        }

        function triggerPost() {
            if(!userToken) return openModal('authModal');
            const text = prompt("ماذا تنشر؟");
            if(text) {
                fetch('/post', {
                    method: 'POST',
                    headers: {'Authorization': 'Bearer '+userToken, 'Content-Type': 'application/json'},
                    body: JSON.stringify({content: text})
                }).then(() => loadFeed());
            }
        }

        // معالجة الروابط المباشرة (Permalink) عند التحميل
        loadFeed();
        const path = window.location.pathname;
        if(path.startsWith('/post/')) {
            const pid = path.split('/')[2];
            showPost(pid);
        }
    </script>
</body>
</html>
"""

@app.route('/')
@app.route('/post/<int:pid>')
def index(pid=None):
    return render_template_string(INDEX_HTML)

# --- تشغيل التطبيق ليتوافق مع الاستضافات (0.0.0.0 & Port 10000) ---
if __name__ == '__main__':
    # الحصول على المنفذ من المتغيرات البيئية (Render/Railway تضع هذا تلقائياً)
    target_port = int(os.environ.get('PORT', 10000))
    # التشغيل على host 0.0.0.0 ليكون متاحاً للإنترنت العام
    app.run(host='0.0.0.0', port=target_port, debug=False)
