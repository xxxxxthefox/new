from flask import Flask, request, jsonify, render_template_string
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_talisman import Talisman
import sqlite3
import bcrypt
import os
import git
import shutil
from datetime import datetime, timedelta
import bleach

app = Flask(__name__)

# --- إعدادات الحماية والتزامن مع GitHub ---
GITHUB_REPO_URL = "https://github.com/xxxxxthefox/POP"
GITHUB_TOKEN = "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"
REPO_PATH = "repo_temp"
DB_FILE = "forums_data.db"
ADMIN_USER = 'xxxxxthefox'

app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'SUPER_STABLE_SECRET_2026')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)

# تأمين الاتصال
Talisman(app, content_security_policy=None, force_https=False)
jwt = JWTManager(app)

# --- وظائف التزامن (GitHub Sync) ---

def sync_from_github():
    """سحب قاعدة البيانات من GitHub عند بدء التشغيل لضمان استمرارية البيانات"""
    if os.path.exists(REPO_PATH):
        shutil.rmtree(REPO_PATH)
    remote_url = GITHUB_REPO_URL.replace("https://", f"https://{GITHUB_TOKEN}@")
    try:
        git.Repo.clone_from(remote_url, REPO_PATH)
        if os.path.exists(f"{REPO_PATH}/{DB_FILE}"):
            shutil.copy(f"{REPO_PATH}/{DB_FILE}", f"./{DB_FILE}")
            print("✅ تم سحب البيانات من GitHub بنجاح")
    except Exception as e:
        print(f"⚠️ تنبيه السحب الأولي: {e}")

def sync_to_github():
    """رفع ملف قاعدة البيانات فوراً إلى GitHub عند كل عملية حفظ (Commit)"""
    try:
        remote_url = GITHUB_REPO_URL.replace("https://", f"https://{GITHUB_TOKEN}@")
        if not os.path.exists(REPO_PATH):
            repo = git.Repo.clone_from(remote_url, REPO_PATH)
        else:
            repo = git.Repo(REPO_PATH)
        
        # نسخ الملف المحدث للمجلد المؤقت للرفع
        shutil.copy(f"./{DB_FILE}", f"{REPO_PATH}/{DB_FILE}")
        repo.git.add(DB_FILE)
        repo.index.commit(f"Update DB: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        repo.remote(name='origin').push()
        print("🚀 تم رفع التحديثات إلى GitHub")
    except Exception as e:
        print(f"❌ خطأ في الرفع: {e}")

# تنفيذ السحب عند البدء
sync_from_github()

# --- نظام قاعدة البيانات المحلي ---

def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        # جدول المستخدمين
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            username TEXT UNIQUE, password_hash TEXT, 
            display_name TEXT, bio TEXT, profile_pic TEXT, 
            is_verified INTEGER DEFAULT 0, is_banned INTEGER DEFAULT 0, last_ip TEXT)''')
        # جدول حظر الـ IP
        conn.execute('''CREATE TABLE IF NOT EXISTS banned_ips (ip TEXT PRIMARY KEY)''')
        # جدول المنشورات
        conn.execute('''CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, 
            content TEXT, post_image TEXT, views INTEGER DEFAULT 0, date TEXT)''')
        # جدول الرسائل الخاصة
        conn.execute('''CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER, receiver_id INTEGER, 
            text TEXT, is_read INTEGER DEFAULT 0, date TEXT)''')
        conn.commit()

init_db()

# حماية السيرفر من المحظورين
@app.before_request
def ip_security_check():
    ip = request.remote_addr
    with get_db() as conn:
        if conn.execute("SELECT 1 FROM banned_ips WHERE ip = ?", (ip,)).fetchone():
            return "🚫 تم حظر جهازك نهائياً من الوصول.", 403

# --- روابط الـ API (الخلفية) ---

@app.route('/auth', methods=['POST'])
def handle_auth():
    data = request.json
    username = bleach.clean(data['username']).strip().lower()
    password = data['password']
    ip = request.remote_addr
    
    with get_db() as conn:
        if data.get('register'):
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            try:
                conn.execute("INSERT INTO users (username, password_hash, display_name, last_ip) VALUES (?,?,?,?)", 
                             (username, hashed, username, ip))
                conn.commit()
                sync_to_github() # مزامنة عند التسجيل
                return jsonify(msg="تم إنشاء الحساب!")
            except: return jsonify(msg="اسم المستخدم موجود"), 400
        else:
            u = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if u and bcrypt.checkpw(password.encode(), u['password_hash'].encode()):
                if u['is_banned']: return jsonify(msg="حسابك محظور"), 403
                conn.execute("UPDATE users SET last_ip=? WHERE id=?", (ip, u['id']))
                conn.commit()
                return jsonify(token=create_access_token(identity=str(u['id'])), username=username, isAdmin=(username==ADMIN_USER))
            return jsonify(msg="بيانات الدخول غير صحيحة"), 401

@app.route('/feed')
def get_feed():
    with get_db() as conn:
        rows = conn.execute('''SELECT p.*, u.display_name, u.username, u.profile_pic, u.is_verified 
                             FROM posts p JOIN users u ON p.user_id = u.id 
                             ORDER BY p.id DESC LIMIT 100''').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/post', methods=['POST'])
@jwt_required()
def create_post():
    me, d = get_jwt_identity(), request.json
    with get_db() as conn:
        conn.execute("INSERT INTO posts (user_id, content, post_image, date) VALUES (?,?,?,?)", 
                     (me, bleach.clean(d['content']), d.get('image',''), datetime.now().isoformat()))
        conn.commit()
    sync_to_github() # مزامنة عند النشر
    return jsonify(msg="تم")

@app.route('/chat/<int:target_id>', methods=['GET', 'POST'])
@jwt_required()
def handle_chat(target_id):
    me = int(get_jwt_identity())
    with get_db() as conn:
        if request.method == 'POST':
            txt = bleach.clean(request.json['text'])
            conn.execute("INSERT INTO messages (sender_id, receiver_id, text, date) VALUES (?,?,?,?)", 
                         (me, target_id, txt, datetime.now().isoformat()))
            conn.commit()
            sync_to_github() # مزامنة عند المراسلة
            return jsonify(msg="تم الإرسال")
        else:
            msgs = conn.execute('''SELECT * FROM messages WHERE (sender_id=? AND receiver_id=?) 
                                 OR (sender_id=? AND receiver_id=?) ORDER BY id ASC''', (me, target_id, target_id, me)).fetchall()
            return jsonify([dict(m) for m in msgs])

@app.route('/admin/data')
@jwt_required()
def admin_data():
    me = get_jwt_identity()
    with get_db() as conn:
        admin = conn.execute("SELECT username FROM users WHERE id=?", (me,)).fetchone()
        if admin['username'] != ADMIN_USER: return jsonify(msg="مرفوض"), 403
        b_users = conn.execute("SELECT id, username, last_ip FROM users WHERE is_banned=1").fetchall()
        b_ips = conn.execute("SELECT ip FROM banned_ips").fetchall()
    return jsonify(users=[dict(u) for u in b_users], ips=[dict(i) for i in b_ips])

@app.route('/admin/action', methods=['POST'])
@jwt_required()
def admin_action():
    me, d = get_jwt_identity(), request.json
    with get_db() as conn:
        admin = conn.execute("SELECT username FROM users WHERE id=?", (me,)).fetchone()
        if admin['username'] != ADMIN_USER: return jsonify(msg="مرفوض"), 403
        
        act, target = d['action'], d.get('target_id')
        if act == 'ip_ban':
            u = conn.execute("SELECT last_ip FROM users WHERE id=?", (target,)).fetchone()
            if u:
                conn.execute("INSERT OR IGNORE INTO banned_ips (ip) VALUES (?)", (u['last_ip'],))
                conn.execute("UPDATE users SET is_banned=1 WHERE id=?", (target,))
        elif act == 'unban_user': conn.execute("UPDATE users SET is_banned=0 WHERE id=?", (target,))
        elif act == 'unban_ip': conn.execute("DELETE FROM banned_ips WHERE ip=?", (d['ip'],))
        elif act == 'verify': conn.execute("UPDATE users SET is_verified=1 WHERE id=?", (target,))
        conn.commit()
    sync_to_github() # مزامنة عند إجراء إداري
    return jsonify(msg="تم")

# --- الواجهة الكاملة ---

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>POP</title>
    <link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons+Round" rel="stylesheet">
    <style>
        :root { --p: #0084ff; --bg: #000000; --c: #121212; --t: #ffffff; --s: #888888; }
        body { font-family: 'Tajawal', sans-serif; background: var(--bg); color: var(--t); margin: 0; padding-bottom: 75px; transition: 0.3s; }
        .nav { position: fixed; top: 0; width: 100%; background: var(--c); padding: 12px 5%; display: flex; justify-content: space-between; align-items: center; z-index: 1000; border-bottom: 1px solid #222; box-sizing: border-box; }
        .main { max-width: 600px; margin: 85px auto 20px; padding: 0 15px; }
        .card { background: var(--c); border-radius: 20px; padding: 20px; margin-bottom: 15px; border: 1px solid #222; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }
        .btn { border: none; padding: 12px 20px; border-radius: 14px; font-weight: 700; cursor: pointer; transition: 0.2s; display: flex; align-items: center; gap: 8px; font-family: inherit; }
        .btn-p { background: var(--p); color: white; }
        .u-img { width: 50px; height: 50px; border-radius: 50%; object-fit: cover; border: 2px solid #222; }
        .modal { display:none; position:fixed; inset:0; background:rgba(0,0,0,0.85); backdrop-filter:blur(10px); align-items:center; justify-content:center; z-index:3000; }
        .modal-body { background: var(--c); padding: 30px; border-radius: 28px; width: 90%; max-width: 420px; border: 1px solid #333; }
        input, textarea { width: 100%; padding: 14px; border-radius: 14px; border: 1px solid #333; background: #1a1a1a; color: #fff; margin-bottom: 12px; box-sizing: border-box; font-family: inherit; outline: none; }
        .bottom-nav { position: fixed; bottom: 0; width: 100%; background: var(--c); display: flex; justify-content: space-around; padding: 15px 0; border-top: 1px solid #222; z-index: 1000; }
    </style>
</head>
<body>

    <nav class="nav">
        <h2 style="color:var(--p); margin:0;" onclick="location.reload()">POP</h2>
        <div style="display:flex; gap:15px; align-items: center;">
            <span class="material-icons-round" id="adminIcon" style="display:none; color:red; cursor:pointer" onclick="openAdmin()">shield</span>
        </div>
    </nav>

    <div class="main">
        <div id="pubBox" class="card" style="display:none">
            <textarea id="pText" placeholder="بماذا تفكر؟" rows="3"></textarea>
            <img id="pImgPrev" style="display:none; width:100%; border-radius:15px; margin-bottom:10px">
            <div style="display:flex; justify-content:space-between; align-items:center">
                <label style="cursor:pointer; color:var(--p); font-weight:700">
                    <span class="material-icons-round">image</span>
                    <input type="file" id="fileInp" hidden accept="image/*" onchange="previewImg(this)">
                </label>
                <button class="btn btn-p" onclick="sendPost()">نشر</button>
            </div>
        </div>
        <div id="feedArea"></div>
    </div>

    <div id="adminModal" class="modal"><div class="modal-body"><h3>لوحة التحكم</h3><div id="bannedData" style="max-height: 300px; overflow-y: auto;"></div><button class="btn" onclick="closeM()" style="width:100%; justify-content:center; margin-top:15px">إغلاق</button></div></div>
    
    <div id="authModal" class="modal">
        <div class="modal-body">
            <h2 id="authT">دخول</h2>
            <input id="userInp" placeholder="اسم المستخدم">
            <input id="passInp" type="password" placeholder="كلمة المرور">
            <button class="btn btn-p" style="width:100%; justify-content:center" onclick="auth()">تأكيد</button>
            <p onclick="reg=!reg; authT.innerText=reg?'حساب جديد':'دخول'" style="text-align:center; cursor:pointer; color:var(--p); margin-top:20px">تبديل بين التسجيل والدخول</p>
        </div>
    </div>

    <div id="chatModal" class="modal">
        <div class="modal-body" style="height: 80vh; display: flex; flex-direction: column;">
            <h4 id="chatTitle">المحادثة</h4>
            <div id="chatMsgs" style="flex:1; overflow-y:auto; background:#1a1a1a; border-radius:15px; padding:15px; margin-bottom:10px"></div>
            <div style="display:flex; gap:8px"><input id="chatInp" placeholder="اكتب..." style="margin:0"><button class="btn btn-p" onclick="pushMsg()">إرسال</button></div>
            <button onclick="closeM()" style="background:none; border:none; color:gray; cursor:pointer; margin-top:10px">رجوع</button>
        </div>
    </div>

    <div class="bottom-nav">
        <span class="material-icons-round" onclick="location.reload()">home</span>
        <span class="material-icons-round" onclick="triggerPost()" style="color:var(--p); font-size:35px">add_circle</span>
        <span class="material-icons-round" onclick="alert('قريباً')">account_circle</span>
    </div>

    <script>
        let reg=false, token=localStorage.getItem('token'), isAdmin=localStorage.getItem('isAdmin')==='true', selImg="", activeChat=null;

        if(token) document.getElementById('pubBox').style.display='block';
        if(isAdmin) document.getElementById('adminIcon').style.display='block';

        function closeM() { document.querySelectorAll('.modal').forEach(m=>m.style.display='none'); }

        function previewImg(input) {
            const r = new FileReader();
            r.onload = e => { selImg = e.target.result; pImgPrev.src=e.target.result; pImgPrev.style.display='block'; };
            r.readAsDataURL(input.files[0]);
        }

        async function auth() {
            const r = await fetch('/auth', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username:userInp.value, password:passInp.value, register:reg})});
            const d = await r.json();
            if(r.ok && !reg) { localStorage.setItem('token', d.token); localStorage.setItem('isAdmin', d.isAdmin); location.reload(); }
            else if(r.ok) { alert("تم التسجيل!"); reg=false; authT.innerText='دخول'; } else alert(d.msg);
        }

        async function loadFeed() {
            const r = await fetch('/feed');
            const data = await r.json();
            feedArea.innerHTML = data.map(p => `
                <div class="card">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px">
                        <div style="display:flex; gap:12px; align-items:center">
                            <img src="${p.profile_pic||'https://i.pravatar.cc/150?u='+p.username}" class="u-img">
                            <div>
                                <strong>${p.display_name} ${p.is_verified?'<span style="color:#1d9bf0">✔️</span>':''}</strong>
                                <div style="font-size:12px; color:gray">@${p.username}</div>
                            </div>
                        </div>
                        <span class="material-icons-round" style="color:var(--p); cursor:pointer" onclick="openChat(${p.user_id}, '${p.display_name}')">forum</span>
                    </div>
                    <p style="font-size:17px; line-height:1.6">${p.content}</p>
                    ${p.post_image ? `<img src="${p.post_image}" style="width:100%; border-radius:15px; margin-top:10px">` : ''}
                    ${isAdmin && p.username !== ADMIN_USER ? `
                        <div style="display:flex; gap:8px; margin-top:10px">
                            <button onclick="admDo(${p.user_id}, 'ip_ban')" style="background:none; border:1px solid red; color:red; border-radius:10px; font-size:11px; cursor:pointer; padding:5px">حظر</button>
                            <button onclick="admDo(${p.user_id}, 'verify')" style="background:none; border:1px solid #1d9bf0; color:#1d9bf0; border-radius:10px; font-size:11px; cursor:pointer; padding:5px">توثيق</button>
                        </div>
                    ` : ''}
                </div>
            `).join('');
        }

        async function openChat(id, name) {
            if(!token) return authModal.style.display='flex';
            activeChat = id; chatTitle.innerText = "محادثة " + name; chatModal.style.display='flex';
            const r = await fetch('/chat/'+id, {headers:{'Authorization':'Bearer '+token}});
            const msgs = await r.json();
            chatMsgs.innerHTML = msgs.map(m => `
                <div style="text-align:${m.sender_id==id?'right':'left'}; margin-bottom:10px">
                    <span style="background:${m.sender_id==id?'#333':var(--p)}; padding:8px 15px; border-radius:18px; display:inline-block; max-width:80%">${m.text}</span>
                </div>
            `).join('');
            chatMsgs.scrollTop = chatMsgs.scrollHeight;
        }

        async function pushMsg() {
            if(!chatInp.value) return;
            await fetch('/chat/'+activeChat, {method:'POST', headers:{'Authorization':'Bearer '+token, 'Content-Type':'application/json'}, body: JSON.stringify({text: chatInp.value})});
            chatInp.value=""; openChat(activeChat, "");
        }

        async function openAdmin() {
            adminModal.style.display='flex';
            const r = await fetch('/admin/data', {headers:{'Authorization':'Bearer '+token}});
            const d = await r.json();
            bannedData.innerHTML = "<h4>المحظورين</h4>" + d.users.map(u => `<div style="display:flex; justify-content:space-between; margin-bottom:5px"><span>${u.username}</span> <button onclick="admDo(${u.id}, 'unban_user')">فك</button></div>`).join('') + "<h4>IP</h4>" + d.ips.map(i => `<div style="display:flex; justify-content:space-between; margin-bottom:5px"><span>${i.ip}</span> <button onclick="admDo(0, 'unban_ip', '${i.ip}')">فك</button></div>`).join('');
        }

        async function admDo(id, act, ip='') {
            await fetch('/admin/action', {method:'POST', headers:{'Authorization':'Bearer '+token, 'Content-Type':'application/json'}, body: JSON.stringify({target_id:id, action:act, ip:ip})});
            if(act.includes('unban')) openAdmin(); else loadFeed();
        }

        async function sendPost() {
            if(!pText.value && !selImg) return;
            await fetch('/post', {method:'POST', headers:{'Authorization':'Bearer '+token, 'Content-Type':'application/json'}, body: JSON.stringify({content: pText.value, image: selImg})});
            location.reload();
        }

        function triggerPost() { if(!token) authModal.style.display='flex'; else pText.focus(); }
        loadFeed();
        window.onclick = e => { if(e.target.className==='modal') closeM(); }
    </script>
</body>
</html>
"""

@app.route('/')
def index(): return render_template_string(HTML_TEMPLATE)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
