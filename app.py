# -*- coding: utf-8 -*-
import os, sqlite3, bcrypt, bleach, datetime, requests, base64, json, uuid
from flask import Flask, request, jsonify, render_template_string, send_from_directory
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from flask_talisman import Talisman

app = Flask(__name__)

# --- الإعدادات السرية والمدمجة ---
GITHUB_TOKEN = "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"
GITHUB_REPO = "xxxxxthefox/POP"
ADMIN_USER = 'xxxxxthefox'
DB_FILE = 'fox_final_v5.db'
UPLOAD_FOLDER = 'uploads'

for folder in [UPLOAD_FOLDER, 'accounts', 'messages_logs']:
    os.makedirs(folder, exist_ok=True)

app.config.update(
    JWT_SECRET_KEY='FOX_ULTIMATE_STAY_LOGGED_IN_INFINITY',
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=20 * 1024 * 1024 # 20MB
)

Talisman(app, content_security_policy=None, force_https=False)
jwt = JWTManager(app)

# --- محرك المزامنة العالمي ---
def sync_to_github(path):
    try:
        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{path}"
        headers = {"Authorization": f"token {GITHUB_TOKEN}"}
        r = requests.get(url, headers=headers)
        sha = r.json().get('sha') if r.status_code == 200 else None
        with open(path, "rb") as f:
            encoded = base64.b64encode(f.read()).decode('utf-8')
        requests.put(url, headers=headers, json={"message": f"Global Sync: {path}", "content": encoded, "sha": sha})
    except: pass

# --- نظام قاعدة البيانات الشامل ---
def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, 
            display_name TEXT, bio TEXT DEFAULT 'عضو في منتديات FOX', 
            profile_pic TEXT DEFAULT 'https://i.pravatar.cc/150?u=fox', 
            role TEXT DEFAULT 'USER', ip TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, content TEXT, 
            views_ips TEXT DEFAULT '[]', created_at TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER, receiver_id INTEGER, 
            msg_text TEXT, sent_at TEXT)''')
        conn.execute("UPDATE users SET role = 'ADMIN' WHERE username = ?", (ADMIN_USER,))
        conn.commit()
init_db()

# --- مسارات API المدمجة ---

@app.route('/uploads/<filename>')
def serve_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/auth', methods=['POST'])
def auth():
    data = request.json
    u, p, reg = data.get('u'), data.get('p'), data.get('reg')
    with get_db() as conn:
        if reg:
            h = bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()
            try:
                conn.execute("INSERT INTO users (username, password_hash, display_name, ip) VALUES (?,?,?,?)", 
                             (u, h, u, request.remote_addr))
                conn.commit()
                sync_to_github(DB_FILE)
                return jsonify(m="Success"), 201
            except: return jsonify(m="Exists"), 400
        else:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (u,)).fetchone()
            if user and bcrypt.checkpw(p.encode(), user['password_hash'].encode()):
                return jsonify(token=create_access_token(identity=str(user['id'])), user=dict(user))
    return jsonify(m="Fail"), 401

@app.route('/api/posts', methods=['GET', 'POST'])
@jwt_required(optional=True)
def posts():
    if request.method == 'POST':
        uid = get_jwt_identity()
        with get_db() as conn:
            conn.execute("INSERT INTO posts (user_id, content, created_at) VALUES (?,?,?)", 
                         (uid, bleach.clean(request.form['content']), datetime.datetime.now().isoformat()))
            conn.commit()
        sync_to_github(DB_FILE)
        return jsonify(m="Ok")
    with get_db() as conn:
        rows = conn.execute("SELECT p.*, u.display_name, u.username, u.profile_pic, u.role FROM posts p JOIN users u ON p.user_id = u.id ORDER BY p.id DESC").fetchall()
        return jsonify([dict(r) for r in rows])

@app.route('/api/profile/upload', methods=['POST'])
@jwt_required()
def upload_profile():
    uid = get_jwt_identity()
    file = request.files.get('pic')
    if file:
        fname = secure_filename(f"fox_{uid}_{uuid.uuid4().hex[:6]}.png")
        path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
        file.save(path)
        url = f"/uploads/{fname}"
        with get_db() as conn:
            conn.execute("UPDATE users SET profile_pic=? WHERE id=?", (url, uid))
            conn.commit()
        sync_to_github(path)
        return jsonify(url=url)
    return jsonify(m="Fail"), 400

@app.route('/api/chat/history/<int:other_id>')
@jwt_required()
def chat_history(other_id):
    uid = get_jwt_identity()
    with get_db() as conn:
        msgs = conn.execute("SELECT * FROM messages WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?) ORDER BY id ASC", 
                            (uid, other_id, other_id, uid)).fetchall()
        return jsonify([dict(m) for m in msgs])

@app.route('/api/chat/send', methods=['POST'])
@jwt_required()
def send_msg():
    uid = get_jwt_identity()
    data = request.json
    with get_db() as conn:
        conn.execute("INSERT INTO messages (sender_id, receiver_id, msg_text, sent_at) VALUES (?,?,?,?)",
                     (uid, data['to_id'], data['txt'], datetime.datetime.now().isoformat()))
        conn.commit()
    return jsonify(m="Sent")

# --- الواجهة الرسومية المطلقة ---
@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>منتديات FOX</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;700;900&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons+Round" rel="stylesheet">
    <style>
        :root { --p: #ff5e00; --bg: #050505; --card: #121212; --t: #ffffff; }
        body { font-family: 'Cairo', sans-serif; background: var(--bg); color: var(--t); margin: 0; padding-bottom: 75px; }
        .header { background: var(--card); padding: 15px; position: sticky; top:0; z-index:100; display:flex; justify-content:space-between; border-bottom: 2px solid var(--p); }
        .post { background: var(--card); border-radius: 20px; padding: 15px; margin: 15px; border: 1px solid #1f1f1f; transition: 0.3s; }
        .post:hover { border-color: var(--p); }
        .avatar { width: 45px; height: 45px; border-radius: 50%; object-fit: cover; border: 2px solid var(--p); cursor:pointer; }
        .nav-bottom { position: fixed; bottom: 0; width: 100%; background: var(--card); display: flex; justify-content: space-around; padding: 12px; border-top: 1px solid #1f1f1f; }
        .modal { display:none; position:fixed; inset:0; background:rgba(0,0,0,0.95); z-index:2000; align-items:center; justify-content:center; backdrop-filter: blur(10px); }
        .m-content { background: var(--card); width: 90%; max-width: 400px; border-radius: 25px; padding: 25px; text-align: center; border: 1px solid var(--p); }
        .btn { background: var(--p); color: white; border: none; padding: 12px; border-radius: 12px; cursor: pointer; width: 100%; font-weight: bold; margin-top: 10px; }
        input, textarea { width: 100%; padding: 12px; margin: 8px 0; border-radius: 12px; border: 1px solid #1f1f1f; background: #000; color: white; box-sizing: border-box; }
        #chatWin { position:fixed; bottom:80px; left:10px; right:10px; background:var(--card); height:450px; border-radius:20px; display:none; flex-direction:column; border:1px solid var(--p); z-index:1500; }
        #msgs { flex:1; overflow-y:auto; padding:15px; display:flex; flex-direction:column; gap:10px; }
        .m_me { background:var(--p); align-self: flex-end; padding:10px; border-radius:15px; font-size:14px; }
        .m_him { background:#252525; align-self: flex-start; padding:10px; border-radius:15px; font-size:14px; }
    </style>
</head>
<body>
    <div class="header"><div style="font-weight: 900; font-size: 24px; color: var(--p);">منتديات FOX 🦊</div><div id="userTop"></div></div>
    
    <div class="container">
        <div id="publishBox" class="post" style="display:none"><textarea id="postTxt" placeholder="أنشر موضوعاً جديداً..."></textarea><button class="btn" onclick="sendPost()">نشر الآن</button></div>
        <div id="mainFeed"></div>
    </div>

    <div id="chatWin">
        <div style="padding:15px; border-bottom:1px solid #1f1f1f; display:flex; justify-content:space-between"><b id="targetName">المراسلة</b><span onclick="document.getElementById('chatWin').style.display='none'">✖</span></div>
        <div id="msgs"></div>
        <div style="padding:10px; display:flex; gap:5px"><input type="text" id="msgInput" placeholder="اكتب رسالة..."><button class="btn" style="width:70px; margin:0" onclick="pushMsg()">إرسال</button></div>
    </div>

    <div id="authModal" class="modal"><div class="m-content"><h2 id="authTitle">دخول FOX</h2><input type="text" id="userIn" placeholder="اليوزر"><input type="password" id="passIn" placeholder="الباسورد"><button class="btn" onclick="submitAuth()">تأكيد</button><p onclick="toggleReg()" id="authSwitch" style="font-size:12px; cursor:pointer; color:var(--p); margin-top:10px">ليس لديك حساب؟ سجل</p></div></div>

    <nav class="nav-bottom">
        <div onclick="location.reload()"><span class="material-icons-round">home</span></div>
        <div onclick="document.getElementById('profileUpload').click()"><span class="material-icons-round">add_a_photo</span></div>
        <input type="file" id="profileUpload" style="display:none" onchange="uploadPic(this)">
        <div onclick="openProfile()"><span class="material-icons-round">person</span></div>
    </nav>

    <script>
        let token = localStorage.getItem('token');
        let user = JSON.parse(localStorage.getItem('user') || '{}');
        let regMode = false; let activeChat = null;

        async function uploadPic(input) {
            let fd = new FormData(); fd.append('pic', input.files[0]);
            const r = await fetch('/api/profile/upload', { method: 'POST', headers: {'Authorization': 'Bearer '+token}, body: fd });
            if(r.ok) location.reload();
        }

        async function submitAuth() {
            const u = document.getElementById('userIn').value; const p = document.getElementById('passIn').value;
            const res = await fetch('/api/auth', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({u, p, reg: regMode}) });
            const data = await res.json();
            if(res.ok) { if(regMode) { location.reload(); } else { localStorage.setItem('token', data.token); localStorage.setItem('user', JSON.stringify(data.user)); location.reload(); } }
        }

        async function loadFeed() {
            const res = await fetch('/api/posts'); const data = await res.json();
            document.getElementById('mainFeed').innerHTML = data.map(p => `
                <div class="post">
                    <div style="display:flex; align-items:center; gap:10px; margin-bottom:10px">
                        <img src="${p.profile_pic}" class="avatar" onclick="startChat(${p.user_id}, '${p.display_name}')">
                        <div><b>${p.display_name}</b> ${p.role==='ADMIN'?'<span style="color:var(--p);font-size:10px">مدير 🦊</span>':''}<div style="font-size:11px; color:gray">@${p.username}</div></div>
                    </div>
                    <div>${p.content}</div>
                </div>`).join('');
        }

        async function startChat(id, name) {
            if(!token) return document.getElementById('authModal').style.display='flex';
            if(id == user.id) return;
            activeChat = id; document.getElementById('targetName').innerText = name; document.getElementById('chatWin').style.display = 'flex';
            const res = await fetch('/api/chat/history/'+id, {headers: {'Authorization': 'Bearer '+token}});
            const msgs = await res.json();
            document.getElementById('msgs').innerHTML = msgs.map(m => `<div class="${m.sender_id == user.id ? 'm_me' : 'm_him'}">${m.msg_text}</div>`).join('');
            document.getElementById('msgs').scrollTop = document.getElementById('msgs').scrollHeight;
        }

        async function pushMsg() {
            const txt = document.getElementById('msgInput').value; if(!txt) return;
            await fetch('/api/chat/send', { method: 'POST', headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer '+token}, body: JSON.stringify({to_id: activeChat, txt}) });
            document.getElementById('msgInput').value = ''; startChat(activeChat, document.getElementById('targetName').innerText);
        }

        async function sendPost() {
            let fd = new FormData(); fd.append('content', document.getElementById('postTxt').value);
            await fetch('/api/posts', {method: 'POST', headers: {'Authorization': 'Bearer '+token}, body: fd}); location.reload();
        }

        function openProfile() { if(!token) document.getElementById('authModal').style.display='flex'; else if(confirm("خروج؟")) { localStorage.clear(); location.reload(); } }
        function toggleReg() { regMode = !regMode; document.getElementById('authTitle').innerText = regMode ? 'إنشاء حساب' : 'دخول FOX'; }

        if(token) { document.getElementById('publishBox').style.display = 'block'; document.getElementById('userTop').innerHTML = `<img src="${user.profile_pic}" class="avatar" style="width:35px; height:35px" onclick="openProfile()">`; }
        else { document.getElementById('userTop').innerHTML = `<button class="btn" style="padding:5px 10px; margin:0" onclick="openProfile()">دخول</button>`; }
        loadFeed();
    </script>
</body>
</html>
    ''')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
