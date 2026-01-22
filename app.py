from flask import Flask, request, jsonify, render_template_string
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import sqlite3
import bcrypt
import os
from datetime import datetime, timedelta
import bleach

app = Flask(__name__)

# --- الإعدادات والحماية ---
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'ultimate-integrated-key-2026')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)

jwt = JWTManager(app)
DB_FILE = 'full_platform.db'

def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            username TEXT UNIQUE, password_hash TEXT,
            display_name TEXT, bio TEXT, profile_pic TEXT DEFAULT 'https://i.pravatar.cc/150?img=3'
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, 
            content TEXT, views INTEGER DEFAULT 0, date TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER, user_id INTEGER, 
            content TEXT, date TEXT)''')
init_db()

# --- الروابط الخلفية (Backend API) ---

@app.route('/auth', methods=['POST'])
def auth():
    data = request.json
    user = bleach.clean(data['username']).strip().lower()
    pw = data['password']
    is_reg = data.get('register', False)
    with get_db() as conn:
        if is_reg:
            hash_pw = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
            try:
                conn.execute("INSERT INTO users (username, password_hash, display_name) VALUES (?,?,?)", (user, hash_pw, user))
                conn.commit()
                return jsonify(msg="تم التسجيل")
            except: return jsonify(msg="المستخدم موجود"), 400
        else:
            u = conn.execute("SELECT * FROM users WHERE username = ?", (user,)).fetchone()
            if u and bcrypt.checkpw(pw.encode(), u['password_hash'].encode()):
                return jsonify(token=create_access_token(identity=str(u['id'])), username=user)
            return jsonify(msg="بيانات خطأ"), 401

@app.route('/feed')
def get_feed():
    with get_db() as conn:
        res = conn.execute('''SELECT p.*, u.display_name, u.username, u.profile_pic,
                           (SELECT COUNT(*) FROM comments WHERE post_id = p.id) as comm_count 
                           FROM posts p JOIN users u ON p.user_id = u.id ORDER BY p.id DESC''').fetchall()
    return jsonify([dict(r) for r in res])

@app.route('/post/<int:pid>')
def get_post_detail(pid):
    with get_db() as conn:
        conn.execute("UPDATE posts SET views = views + 1 WHERE id = ?", (pid,))
        post = conn.execute('SELECT p.*, u.display_name, u.username, u.profile_pic FROM posts p JOIN users u ON p.user_id = u.id WHERE p.id = ?', (pid,)).fetchone()
        comms = conn.execute('SELECT c.*, u.display_name, u.username, u.profile_pic FROM comments c JOIN users u ON c.user_id = u.id WHERE c.post_id = ?', (pid,)).fetchall()
        if post: return jsonify(post=dict(post), comments=[dict(c) for c in comms])
    return jsonify(msg="غير موجود"), 404

@app.route('/profile/me')
@jwt_required()
def my_profile():
    uid = get_jwt_identity()
    with get_db() as conn:
        u = conn.execute("SELECT username, display_name, bio, profile_pic FROM users WHERE id = ?", (uid,)).fetchone()
    return jsonify(dict(u))

@app.route('/profile/update', methods=['POST'])
@jwt_required()
def update_profile():
    uid = get_jwt_identity()
    d = request.json
    with get_db() as conn:
        conn.execute("UPDATE users SET display_name=?, bio=?, profile_pic=? WHERE id=?", 
                     (bleach.clean(d['display_name']), bleach.clean(d['bio']), bleach.clean(d['profile_pic']), uid))
        conn.commit()
    return jsonify(msg="تم")

@app.route('/post', methods=['POST'])
@jwt_required()
def create_post():
    uid = get_jwt_identity()
    with get_db() as conn:
        conn.execute("INSERT INTO posts (user_id, content, date) VALUES (?,?,?)", 
                     (uid, bleach.clean(request.json['content']), datetime.now().isoformat()))
    return jsonify(msg="تم")

@app.route('/comment', methods=['POST'])
@jwt_required()
def add_comment():
    uid = get_jwt_identity()
    d = request.json
    with get_db() as conn:
        conn.execute("INSERT INTO comments (post_id, user_id, content, date) VALUES (?,?,?,?)", 
                     (d['pid'], uid, bleach.clean(d['content']), datetime.now().isoformat()))
    return jsonify(msg="تم")

# --- الواجهة الأمامية (Frontend) ---

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>فـول - FOOL</title>
    <link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons+Round" rel="stylesheet">
    <style>
        :root { --p: #6366f1; --bg: #f3f4f6; --c: #ffffff; --t: #111827; }
        [data-theme="dark"] { --bg: #0b0f1a; --c: #161e2e; --t: #f9fafb; }
        body { font-family: 'Tajawal', sans-serif; background: var(--bg); color: var(--t); margin: 0; transition: 0.3s; padding-bottom: 70px; }
        .nav { position: fixed; top: 0; width: 100%; background: var(--c); padding: 12px 5%; display: flex; justify-content: space-between; align-items: center; box-sizing: border-box; z-index: 1000; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .main { max-width: 600px; margin: 80px auto 20px; padding: 0 15px; }
        .card { background: var(--c); border-radius: 20px; padding: 20px; margin-bottom: 15px; box-shadow: 0 4px 10px rgba(0,0,0,0.05); border: 1px solid rgba(0,0,0,0.05); transition: 0.2s; }
        .p-img { width: 45px; height: 45px; border-radius: 50%; object-fit: cover; }
        .btn { border: none; padding: 10px 20px; border-radius: 12px; font-weight: bold; cursor: pointer; }
        .btn-p { background: var(--p); color: white; }
        .bottom-nav { position: fixed; bottom: 0; width: 100%; background: var(--c); display: flex; justify-content: space-around; padding: 10px 0; border-top: 1px solid rgba(0,0,0,0.1); z-index: 1000; }
        .nav-item { color: gray; text-align: center; font-size: 11px; cursor: pointer; }
        .modal { display:none; position:fixed; inset:0; background:rgba(0,0,0,0.5); backdrop-filter:blur(5px); align-items:center; justify-content:center; z-index:3000; }
        #fullPostView { display:none; position:fixed; inset:0; background:var(--bg); z-index:2000; overflow-y:auto; padding-top:60px; }
        input, textarea { width: 100%; padding: 12px; border-radius: 12px; border: 1px solid rgba(0,0,0,0.1); background: var(--bg); color: var(--t); outline: none; box-sizing: border-box; font-family: inherit; }
    </style>
</head>
<body data-theme="light">

    <nav class="nav">
        <h2 style="color:var(--p); margin:0;" onclick="location.href='/'">فـول</h2>
        <span class="material-icons-round" onclick="toggleTheme()" style="cursor:pointer">dark_mode</span>
    </nav>

    <div class="main" id="homeFeed">
        <div class="card" onclick="checkPost()" style="cursor:pointer; color:gray">ماذا يخطر في بالك؟ انشر الآن...</div>
        <div id="feedArea"></div>
    </div>

    <div id="fullPostView">
        <div class="nav"><button class="btn" onclick="closePost()"><span class="material-icons-round">arrow_forward</span></button></div>
        <div class="main" id="postContent"></div>
    </div>

    <div class="bottom-nav">
        <div class="nav-item" onclick="location.reload()"><span class="material-icons-round">home</span><br>الرئيسية</div>
        <div class="nav-item" onclick="openProfile()"><span class="material-icons-round">person</span><br>ملفي</div>
    </div>

    <div id="authM" class="modal">
        <div class="card" style="width:320px">
            <h3 id="aTitle">دخول</h3>
            <input id="u" placeholder="اسم المستخدم"><br><br>
            <input id="p" type="password" placeholder="كلمة المرور"><br><br>
            <button class="btn btn-p" style="width:100%" onclick="auth()">تأكيد</button>
            <p onclick="reg=!reg; document.getElementById('aTitle').innerText=reg?'جديد':'دخول'" style="text-align:center; font-size:12px; cursor:pointer">تبديل</p>
        </div>
    </div>

    <div id="profM" class="modal">
        <div class="card" style="width:350px">
            <h3>تعديل الملف</h3>
            <input id="dn" placeholder="الاسم المستعار"><br><br>
            <input id="pp" placeholder="رابط الصورة الشخصية"><br><br>
            <textarea id="bi" placeholder="وصف قصير..."></textarea><br><br>
            <button class="btn btn-p" style="width:100%" onclick="saveProf()">حفظ</button>
            <button class="btn" style="width:100%" onclick="closeM()">إغلاق</button>
        </div>
    </div>

    <script>
        let reg = false, token = localStorage.getItem('token');
        function toggleTheme() { document.body.setAttribute('data-theme', document.body.getAttribute('data-theme')==='light'?'dark':'light'); }
        function openM(id) { document.getElementById(id).style.display='flex'; }
        function closeM() { document.querySelectorAll('.modal').forEach(m=>m.style.display='none'); }

        async function auth() {
            const r = await fetch('/auth', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username:u.value, password:p.value, register:reg})});
            const d = await r.json();
            if(r.ok && !reg) { localStorage.setItem('token', d.token); location.reload(); } else if(r.ok) { alert("تم!"); reg=false; } else alert(d.msg);
        }

        async function loadFeed() {
            const r = await fetch('/feed');
            const data = await r.json();
            document.getElementById('feedArea').innerHTML = data.map(p => `
                <div class="card" onclick="viewPost(${p.id})">
                    <div style="display:flex; gap:10px; align-items:center; margin-bottom:10px">
                        <img src="${p.profile_pic}" class="p-img">
                        <div><strong>${p.display_name}</strong><br><small style="color:gray">@${p.username}</small></div>
                    </div>
                    <div style="font-size:17px">${p.content}</div>
                    <div style="margin-top:10px; font-size:12px; color:gray">👁️ ${p.views} | 💬 ${p.comm_count}</div>
                </div>
            `).join('');
        }

        async function viewPost(pid) {
            const r = await fetch('/post/'+pid);
            const d = await r.json(); const p = d.post;
            window.history.pushState({}, '', '/post/'+pid);
            document.getElementById('fullPostView').style.display='block';
            document.getElementById('postContent').innerHTML = `
                <div class="card">
                    <div style="display:flex; gap:10px; align-items:center">
                        <img src="${p.profile_pic}" class="p-img">
                        <strong>${p.display_name}</strong>
                    </div>
                    <p style="font-size:20px">${p.content}</p>
                </div>
                <h4>التعليقات (${d.comments.length})</h4>
                ${token ? `<textarea id="ci" placeholder="اكتب تعليقاً..."></textarea><button class="btn btn-p" onclick="addC(${pid})">تعليق</button>` : ''}
                <div id="cArea">${d.comments.map(c=>`<div style="margin-top:10px; border-bottom:1px solid #eee; padding:5px"><strong>${c.display_name}:</strong> ${c.content}</div>`).join('')}</div>
            `;
        }

        function closePost() { document.getElementById('fullPostView').style.display='none'; window.history.pushState({}, '', '/'); loadFeed(); }

        async function openProfile() {
            if(!token) return openM('authM');
            const r = await fetch('/profile/me', {headers:{'Authorization':'Bearer '+token}});
            const d = await r.json();
            dn.value=d.display_name; pp.value=d.profile_pic; bi.value=d.bio||'';
            openM('profM');
        }

        async function saveProf() {
            await fetch('/profile/update', {method:'POST', headers:{'Authorization':'Bearer '+token, 'Content-Type':'application/json'}, body:JSON.stringify({display_name:dn.value, profile_pic:pp.value, bio:bi.value})});
            location.reload();
        }

        function checkPost() {
            if(!token) openM('authM');
            else { const c = prompt("ماذا تنشر؟"); if(c) fetch('/post', {method:'POST', headers:{'Authorization':'Bearer '+token, 'Content-Type':'application/json'}, body:JSON.stringify({content:c})}).then(()=>loadFeed()); }
        }

        async function addC(pid) {
            await fetch('/comment', {method:'POST', headers:{'Authorization':'Bearer '+token, 'Content-Type':'application/json'}, body:JSON.stringify({pid, content:ci.value})});
            viewPost(pid);
        }

        loadFeed();
        // تفعيل Permalink عند الدخول المباشر
        if(window.location.pathname.startsWith('/post/')) viewPost(window.location.pathname.split('/')[2]);
    </script>
</body>
</html>
"""

@app.route('/')
@app.route('/post/<int:pid>')
def index(pid=None): return render_template_string(HTML_TEMPLATE)

if __name__ == '__main__':
    app.run(debug=True)
