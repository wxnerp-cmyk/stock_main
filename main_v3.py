"""
stock_main v3.0 - 路由主服务 + 登录/权限 + 管理后台
iframe 直连子服务, 不经过网关代理
"""
import threading, time, uuid, hashlib, secrets, requests
from datetime import datetime
from flask import Flask, request, jsonify, Response, session, redirect, url_for
import pymysql

DB_CONFIG = {
    'host': '192.168.0.106', 'port': 3304,
    'user': 'zhq', 'password': 'zhq1', 'database': 'd_lnx_tqhq'
}
CENTER_PORT = 9000
HEARTBEAT_INTERVAL = 10
MAX_HEARTBEAT_FAILS = 3

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

def get_db(): return pymysql.connect(**DB_CONFIG)

def db_exec(sql, params=()):
    conn = get_db(); cur = conn.cursor()
    cur.execute(sql, params); conn.commit()
    r = cur.fetchall() if cur.description else []
    conn.close(); return r

def db_one(sql, params=()):
    rows = db_exec(sql, params); return rows[0] if rows else None

def init_db():
    conn = pymysql.connect(**DB_CONFIG); cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS service_registry (id INT AUTO_INCREMENT PRIMARY KEY, service_name VARCHAR(100) UNIQUE NOT NULL, host VARCHAR(50) NOT NULL, port INT NOT NULL, service_token VARCHAR(64) NOT NULL, routes TEXT, status VARCHAR(20) DEFAULT 'ONLINE', last_heartbeat DATETIME NULL, register_time DATETIME NULL, heartbeat_fail_count INT DEFAULT 0) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL, password_hash VARCHAR(128) NOT NULL, is_admin TINYINT DEFAULT 0, status TINYINT DEFAULT 1, create_time DATETIME NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")
    cur.execute("CREATE TABLE IF NOT EXISTS tq_accounts (id INT AUTO_INCREMENT PRIMARY KEY, account_name VARCHAR(100) NOT NULL, tq_username VARCHAR(100) NOT NULL, tq_password VARCHAR(100) NOT NULL, status TINYINT DEFAULT 1, create_time DATETIME NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")
    cur.execute("CREATE TABLE IF NOT EXISTS modules (id INT AUTO_INCREMENT PRIMARY KEY, module_name VARCHAR(100) NOT NULL, module_key VARCHAR(50) UNIQUE NOT NULL, service_name VARCHAR(100) NOT NULL, route_path VARCHAR(200) NOT NULL, icon VARCHAR(10) DEFAULT 'icon', sort_order INT DEFAULT 0, status TINYINT DEFAULT 1) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")
    cur.execute("CREATE TABLE IF NOT EXISTS user_accounts (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, account_id INT NOT NULL, UNIQUE KEY uk_ua (user_id, account_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")
    cur.execute("CREATE TABLE IF NOT EXISTS user_module_permissions (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, module_id INT NOT NULL, UNIQUE KEY uk_um (user_id, module_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")
    if not db_one("SELECT 1 FROM users WHERE username='admin'"):
        pw = hashlib.sha256('admin123'.encode()).hexdigest()
        cur.execute("INSERT INTO users (username,password_hash,is_admin) VALUES ('admin',%s,1)", (pw,))
    if not db_one("SELECT 1 FROM tq_accounts"):
        cur.execute("INSERT INTO tq_accounts (account_name,tq_username,tq_password) VALUES ('zhubajie','zhubajie','jinhu303')")
    if not db_one("SELECT 1 FROM modules"):
        cur.execute("INSERT INTO modules (module_name,module_key,service_name,route_path,icon,sort_order) VALUES ('KLine','quotes','stock-app-01','/','📈',1),('KLineAPI','kline','stock-app-01','/api/kline','📉',2),('Expiry','expiry','stock-app-01','/option-expiry','📅',3)")
    conn.commit(); conn.close()
    print("[DB] 6 tables ready")

def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

def login_required(f):
    from functools import wraps
    @wraps(f)
    def w(*a,**k):
        if 'user_id' not in session: return redirect('/login')
        return f(*a,**k)
    return w

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def w(*a,**k):
        if 'user_id' not in session: return redirect('/login')
        if not session.get('is_admin'): return '<h3>403</h3>',403
        return f(*a,**k)
    return w

def get_user_modules(uid):
    if session.get('is_admin'):
        rows = db_exec("SELECT module_name,module_key,service_name,route_path,icon FROM modules WHERE status=1 ORDER BY sort_order")
    else:
        rows = db_exec("SELECT m.module_name,m.module_key,m.service_name,m.route_path,m.icon FROM modules m JOIN user_module_permissions p ON m.id=p.module_id WHERE p.user_id=%s AND m.status=1 ORDER BY m.sort_order",(uid,))
    return [{'name':r[0],'key':r[1],'service':r[2],'route':r[3],'icon':r[4]} for r in rows]

def get_user_accounts(uid):
    rows = db_exec("SELECT a.id,a.account_name,a.tq_username FROM tq_accounts a JOIN user_accounts ua ON a.id=ua.account_id WHERE ua.user_id=%s AND a.status=1",(uid,))
    return [{'id':r[0],'name':r[1],'username':r[2]} for r in rows]

# ===== HEARTBEAT =====
def hb():
    while True:
        try:
            for name,host,port,token,fc in db_exec("SELECT service_name,host,port,service_token,heartbeat_fail_count FROM service_registry WHERE status='ONLINE'"):
                try:
                    r = requests.get(f"http://{host}:{port}/health",params={'token':token},timeout=5)
                    if r.status_code==200 and r.json().get('alive'):
                        db_exec("UPDATE service_registry SET last_heartbeat=%s,heartbeat_fail_count=0 WHERE service_name=%s",(datetime.now(),name))
                    else: fc+=1; hbf(name,fc)
                except: fc+=1; hbf(name,fc)
        except: pass
        time.sleep(HEARTBEAT_INTERVAL)

def hbf(n,fc):
    if fc>=MAX_HEARTBEAT_FAILS:
        db_exec("UPDATE service_registry SET status='OFFLINE',heartbeat_fail_count=%s WHERE service_name=%s",(fc,n))
    else: db_exec("UPDATE service_registry SET heartbeat_fail_count=%s WHERE service_name=%s",(fc,n))

# ===== REGISTRY API =====
@app.route('/register',methods=['POST'])
def api_svc_reg():
    d=request.get_json(force=True)
    sn,ho,po = d['service_name'],d['host'],d['port']
    rt=d.get('routes',''); tk=str(uuid.uuid4())
    if db_one("SELECT 1 FROM service_registry WHERE service_name=%s",(sn,)):
        db_exec("UPDATE service_registry SET host=%s,port=%s,service_token=%s,routes=%s,status='ONLINE',last_heartbeat=%s,heartbeat_fail_count=0 WHERE service_name=%s",(ho,po,tk,rt,datetime.now(),sn))
    else: db_exec("INSERT INTO service_registry (service_name,host,port,service_token,routes) VALUES (%s,%s,%s,%s,%s)",(sn,ho,po,tk,rt))
    return jsonify({'code':0,'service_token':tk})

@app.route('/unregister',methods=['POST'])
def api_svc_unreg():
    t=request.get_json(force=True).get('service_token','')
    if t: db_exec("UPDATE service_registry SET status='OFFLINE' WHERE service_token=%s",(t,))
    return jsonify({'code':0})

# ===== LOGIN PAGE =====
LOGIN_HTML = r'''<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><title>Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Microsoft YaHei',sans-serif;background:#0d1117;color:#c9d1d9;display:flex;justify-content:center;align-items:center;min-height:100vh}
.box{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:40px;width:380px}
h2{color:#58a6ff;text-align:center;margin-bottom:24px}
input{width:100%;padding:10px 14px;margin-bottom:14px;border-radius:6px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;font-size:14px}
input:focus{outline:none;border-color:#58a6ff}
.btn{width:100%;padding:10px;border-radius:6px;border:none;background:#238636;color:#fff;font-size:15px;cursor:pointer;margin-bottom:10px}
.btn:hover{background:#2ea043}
.btn2{background:#21262d}.btn2:hover{background:#30363d}
.error{color:#f85149;font-size:13px;margin-bottom:10px;text-align:center}
.tip{text-align:center;font-size:12px;color:#8b949e;margin-top:16px}
</style></head><body>
<div class="box"><h2>TQ System</h2>
<div class="error" id="err"></div>
<input id="u" placeholder="Username"><input id="p" type="password" placeholder="Password">
<button class="btn" onclick="login()">Login</button>
<button class="btn btn2" onclick="reg()">Register</button>
<div class="tip">Default: admin / admin123</div>
</div><script>
function login(){fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})}).then(r=>r.json()).then(d=>{if(d.code==0)location.href='/app';else document.getElementById('err').textContent=d.msg})}
function reg(){var u=document.getElementById('u').value,p=document.getElementById('p').value;if(!u||!p){document.getElementById('err').textContent='Please fill all fields';return}if(p.length<6){document.getElementById('err').textContent='Password min 6 chars';return}fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})}).then(r=>r.json()).then(d=>{if(d.code==0){document.getElementById('err').textContent='Registered! Please login.';document.getElementById('err').style.color='#26a641'}else document.getElementById('err').textContent=d.msg})}
</script></body></html>'''

@app.route('/login')
@app.route('/')
def login_page():
    if 'user_id' in session: return redirect('/app')
    return LOGIN_HTML

@app.route('/api/login',methods=['POST'])
def api_login():
    d=request.get_json(force=True)
    u=d.get('username',''); p=hash_pw(d.get('password',''))
    row=db_one("SELECT id,is_admin FROM users WHERE username=%s AND password_hash=%s AND status=1",(u,p))
    if not row: return jsonify({'code':-1,'msg':'Invalid credentials'})
    session['user_id']=row[0]; session['username']=u; session['is_admin']=bool(row[1])
    accts=get_user_accounts(row[0])
    if accts: session['current_account_id']=accts[0]['id']; session['current_account_name']=accts[0]['name']
    return jsonify({'code':0})

@app.route('/api/register',methods=['POST'])
def api_user_reg():
    d=request.get_json(force=True); u=d.get('username',''); p=d.get('password','')
    if not u or len(p)<6: return jsonify({'code':-1,'msg':'Invalid params'})
    if db_one("SELECT 1 FROM users WHERE username=%s",(u,)): return jsonify({'code':-1,'msg':'Username exists'})
    db_exec("INSERT INTO users (username,password_hash) VALUES (%s,%s)",(u,hash_pw(p)))
    return jsonify({'code':0})

@app.route('/logout')
def logout(): session.clear(); return redirect('/login')

# ===== API: get service URL for frontend =====
@app.route('/api/service_url/<module_key>')
@login_required
def api_service_url(module_key):
    """返回模块对应子服务的直连URL + 当前账户信息"""
    mod = db_one("SELECT service_name,route_path FROM modules WHERE module_key=%s AND status=1",(module_key,))
    if not mod: return jsonify({'code':-1,'msg':'Module not found'}),404
    svc = db_one("SELECT host,port FROM service_registry WHERE service_name=%s AND status='ONLINE'",(mod[0],))
    if not svc: return jsonify({'code':-1,'msg':'Service offline'}),503
    host, port = svc
    route = mod[1]
    url = f"http://{host}:{port}{route}"
    # 附上天勤账户参数
    params = {}
    aid = session.get('current_account_id')
    if aid:
        ac = db_one("SELECT tq_username,tq_password FROM tq_accounts WHERE id=%s",(aid,))
        if ac:
            params['tq_user'] = ac[0]
            params['tq_pass'] = ac[1]
    return jsonify({'code':0,'url':url,'params':params})

@app.route('/api/acct/switch',methods=['POST'])
def api_switch():
    d=request.get_json(force=True)
    session['current_account_id']=d['account_id']
    session['current_account_name']=d['account_name']
    return jsonify({'code':0})

# ===== MAIN APP SHELL =====
@app.route('/app')
@login_required
def app_main():
    uid=session['user_id']
    accts=get_user_accounts(uid)
    mods=get_user_modules(uid)
    is_admin=session.get('is_admin',False)
    acct_opts=''.join('<option value="{}" {}>{}</option>'.format(a['id'],'selected' if str(a['id'])==str(session.get('current_account_id','')) else '',a['name']+' ('+a['username']+')') for a in accts)
    nav=''.join('<a href="#" class="nav-item" onclick="sw(\'{}\',\'{}\')" data-key="{}"><span>{}</span> {}</a>'.format(m['key'],m['route'],m['key'],m['icon'],m['name']) for m in mods)
    adm='<a href="/admin" class="nav-item adm">Settings</a>' if is_admin else ''
    return '''<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><title>TQ System</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Microsoft YaHei',sans-serif;background:#0d1117;color:#c9d1d9;display:flex;height:100vh;overflow:hidden}
.sb{width:200px;background:#161b22;border-right:1px solid #30363d;display:flex;flex-direction:column}
.sb-h{padding:16px;border-bottom:1px solid #30363d}
.sb-h h3{color:#58a6ff;font-size:15px}
.sb-n{flex:1;padding:8px}
.nav-item{display:flex;align-items:center;gap:8px;padding:10px 12px;color:#8b949e;text-decoration:none;border-radius:6px;margin-bottom:4px;font-size:13px;transition:all .2s}
.nav-item:hover{background:#1c2129;color:#c9d1d9}
.nav-item.active{background:#1f6feb22;color:#58a6ff;border-left:3px solid #58a6ff}
.nav-item.adm{color:#f0c000!important}
.main{flex:1;display:flex;flex-direction:column}
.tb{height:48px;background:#161b22;border-bottom:1px solid #30363d;display:flex;align-items:center;justify-content:space-between;padding:0 16px}
.tb select{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;padding:4px 8px;font-size:12px}
.tb .usr{color:#58a6ff}
.tb a{color:#f85149;text-decoration:none;font-size:12px}
.ct{flex:1;overflow:auto;padding:0}
.ct iframe{width:100%;height:100%;border:none}
</style></head><body>
<div class="sb"><div class="sb-h"><h3>TQ System</h3><p style="font-size:11px;color:#8b949e">'''+session.get('username','')+'''</p></div><div class="sb-n">'''+nav+adm+'''</div></div>
<div class="main"><div class="tb"><div><b style="color:#58a6ff">Gateway</b></div><div style="display:flex;align-items:center;gap:12px;font-size:13px"><span>Account:</span><select id="acs" onchange="swa()">'''+acct_opts+'''</select><span class="usr">'''+session.get('username','')+'''</span><a href="/logout">Exit</a></div></div>
<div class="ct"><iframe id="fr" src=""></iframe></div></div>
<script>
var cm='quotes',cr='/';
function sw(k,r){cm=k;cr=r;document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));document.querySelector('[data-key="'+k+'"]').classList.add('active');ld()}
function ld(){
  fetch('/api/service_url/'+cm).then(r=>r.json()).then(d=>{
    if(d.code==0){
      var u=d.url;
      if(d.params && Object.keys(d.params).length>0){
        u+=(d.url.includes('?')?'&':'?')+Object.entries(d.params).map(function(e){return e[0]+'='+encodeURIComponent(e[1])}).join('&');
      }
      document.getElementById('fr').src=u;
    }
  });
}
function swa(){
  var s=document.getElementById('acs');
  var ai=s.value,an=s.options[s.selectedIndex]?.text.split(' (')[0]||'';
  fetch('/api/acct/switch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({account_id:parseInt(ai),account_name:an})}).then(r=>r.json()).then(d=>{if(d.code==0)ld()});
}
ld();
</script></body></html>'''

# ===== ADMIN PANEL =====
@app.route('/admin')
@admin_required
def admin():
    return r'''<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><title>Admin</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Microsoft YaHei',sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}
h1{color:#58a6ff;margin-bottom:20px}
.tabs{display:flex;gap:8px;margin-bottom:20px}
.tab{padding:8px 20px;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#8b949e;cursor:pointer;font-size:13px}
.tab:hover{color:#c9d1d9}.tab.active{background:#1f6feb22;border-color:#58a6ff;color:#58a6ff}
.panel{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:12px}
th{background:#0d1117;padding:8px 12px;text-align:left;border-bottom:2px solid #30363d;color:#58a6ff}
td{padding:6px 12px;border-bottom:1px solid #21262d}
button{padding:4px 12px;border-radius:4px;border:1px solid #30363d;background:#21262d;color:#c9d1d9;cursor:pointer;font-size:12px;margin:2px}
button:hover{background:#30363d}.btn-d{color:#f85149;border-color:#f85149}
input,select{padding:6px 10px;border-radius:4px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;font-size:12px;margin:2px}
.frow{display:flex;gap:8px;align-items:center;margin-bottom:12px;flex-wrap:wrap}
.g{color:#26a641}.r{color:#f85149}.y{color:#f0c000}
</style></head><body>
<h1>Admin Panel</h1>
<div class="tabs"><button class="tab active" onclick="st('users')">Users</button><button class="tab" onclick="st('accounts')">Accounts</button><button class="tab" onclick="st('modules')">Modules</button><button class="tab" onclick="st('services')">Services</button></div>
<div id="pn" class="panel">Loading...</div>
<script>
var ct='users';function st(t){ct=t;document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active'));event.target.classList.add('active');lt()}
function lt(){fetch('/admin/api/'+ct).then(r=>r.json()).then(d=>{document.getElementById('pn').innerHTML=d.html})}
function ap(url,data,cb){fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data||{})}).then(r=>r.json()).then(cb)}
lt();
</script></body></html>'''

@app.route('/admin/api/users')
@admin_required
def a_users():
    rows=db_exec("SELECT id,username,is_admin,status,create_time FROM users ORDER BY id")
    h='<div class="frow"><input id="nu" placeholder="username"><input id="np" type="password" placeholder="password"><button onclick="addu()">Add</button></div><table><tr><th>ID</th><th>Username</th><th>Admin</th><th>Status</th><th>Created</th><th>Actions</th></tr>'
    for r in rows:
        h+='<tr><td>'+str(r[0])+'</td><td>'+str(r[1])+'</td><td>'+('Y' if r[2] else '')+'</td><td class="'+('g' if r[3] else 'r')+'">'+('Active' if r[3] else 'Disabled')+'</td><td>'+str(r[4] or '')+'</td><td>'
        if not r[2]: h+='<button onclick="tgu('+str(r[0])+','+str(0 if r[3] else 1)+')">'+('Disable' if r[3] else 'Enable')+'</button>'
        h+='<button class="btn-d" onclick="du('+str(r[0])+')">Del</button></td></tr>'
    h+='</table><scr'+'ipt>function addu(){var u=document.getElementById("nu").value,p=document.getElementById("np").value;ap("/admin/api/user_add",{username:u,password:p},function(d){if(d.code==0)lt();else alert(d.msg)})}function tgu(id,s){ap("/admin/api/user_toggle",{user_id:id,status:s},lt)}function du(id){if(confirm("Delete?"))ap("/admin/api/user_del",{user_id:id},lt)}</scr'+'ipt>'
    return jsonify({'code':0,'html':h})

@app.route('/admin/api/accounts')
@admin_required
def a_accounts():
    rows=db_exec("SELECT id,account_name,tq_username,status FROM tq_accounts ORDER BY id")
    h='<div class="frow"><input id="an" placeholder="alias"><input id="au" placeholder="tq user"><input id="ap" type="password" placeholder="tq pass"><button onclick="adda()">Add</button></div><table><tr><th>ID</th><th>Alias</th><th>TQ User</th><th>Status</th><th>Actions</th></tr>'
    for r in rows:
        h+='<tr><td>'+str(r[0])+'</td><td>'+str(r[1])+'</td><td>'+str(r[2])+'</td><td class="'+('g' if r[3] else 'r')+'">'+('Active' if r[3] else 'Disabled')+'</td><td><button onclick="tga('+str(r[0])+','+str(0 if r[3] else 1)+')">'+('Disable' if r[3] else 'Enable')+'</button></td></tr>'
    h+='</table><scr'+'ipt>function adda(){ap("/admin/api/account_add",{name:document.getElementById("an").value,user:document.getElementById("au").value,pass:document.getElementById("ap").value},lt)}function tga(id,s){ap("/admin/api/account_toggle",{id:id,status:s},lt)}</scr'+'ipt>'
    return jsonify({'code':0,'html':h})

@app.route('/admin/api/modules')
@admin_required
def a_modules():
    users=db_exec("SELECT id,username FROM users WHERE status=1 ORDER BY id")
    opts=''.join('<option value="'+str(u[0])+'">'+str(u[1])+'</option>' for u in users)
    h='<div class="frow"><select id="pu">'+opts+'</select><button onclick="lp()">View Perms</button></div><div id="pr"></div><scr'+'ipt>function lp(){var uid=document.getElementById("pu").value;if(!uid)return;fetch("/admin/api/user_perms?user_id="+uid).then(r=>r.json()).then(d=>{document.getElementById("pr").innerHTML=d.html})}</scr'+'ipt>'
    return jsonify({'code':0,'html':h})

@app.route('/admin/api/user_perms')
@admin_required
def a_user_perms():
    uid=request.args.get('user_id','')
    if not uid: return jsonify({'html':''})
    mods=db_exec("SELECT id,module_name,module_key FROM modules WHERE status=1 ORDER BY sort_order")
    up={r[0] for r in db_exec("SELECT module_id FROM user_module_permissions WHERE user_id=%s",(uid,))}
    h='<table><tr><th>Module</th><th>Status</th><th>Action</th></tr>'
    for mid,mn,mk in mods:
        has=mid in up
        h+='<tr><td>'+mn+' ('+mk+')</td><td class="'+('g' if has else 'r')+'">'+('Y' if has else 'N')+'</td><td><button onclick="tp('+uid+','+str(mid)+','+str(0 if has else 1)+')">'+('Revoke' if has else 'Grant')+'</button></td></tr>'
    h+='</table><hr><div class="frow"><b>Assign account:</b><select id="asel"><option value="">Select</option>'+''.join('<option value="'+str(a[0])+'">'+str(a[1])+' ('+str(a[2])+')</option>' for a in db_exec("SELECT id,account_name,tq_username FROM tq_accounts WHERE status=1"))+'</select><button onclick="aa('+uid+')">Assign</button></div><div id="al"></div><scr'+'ipt>function tp(uid,mid,v){ap("/admin/api/perm_toggle",{user_id:uid,module_id:mid,value:v},lp)}function aa(uid){var aid=document.getElementById("asel").value;if(!aid)return;ap("/admin/api/assign_account",{user_id:uid,account_id:parseInt(aid)},lp)}fetch("/admin/api/user_accounts?user_id="+'+uid+').then(r=>r.json()).then(d=>{document.getElementById("al").innerHTML=d.html})</scr'+'ipt>'
    return jsonify({'code':0,'html':h})

@app.route('/admin/api/user_accounts')
@admin_required
def a_ua():
    uid=request.args.get('user_id','')
    rows=db_exec("SELECT a.id,a.account_name,a.tq_username FROM tq_accounts a JOIN user_accounts ua ON a.id=ua.account_id WHERE ua.user_id=%s",(uid,))
    h='<table><tr><th>ID</th><th>Alias</th><th>TQ</th><th>Action</th></tr>'
    for r in rows:
        h+='<tr><td>'+str(r[0])+'</td><td>'+str(r[1])+'</td><td>'+str(r[2])+'</td><td><button class="btn-d" onclick="ua('+uid+','+str(r[0])+')">Remove</button></td></tr>'
    h+='</table><scr'+'ipt>function ua(uid,aid){ap("/admin/api/unassign_account",{user_id:uid,account_id:aid},lp)}</scr'+'ipt>'
    return jsonify({'code':0,'html':h})

@app.route('/admin/api/services')
@admin_required
def a_services():
    rows=db_exec("SELECT service_name,host,port,status,last_heartbeat,heartbeat_fail_count,routes FROM service_registry ORDER BY register_time DESC")
    h='<table><tr><th>Name</th><th>Addr</th><th>Status</th><th>Last HB</th><th>Fails</th><th>Routes</th></tr>'
    for r in rows:
        cls='g' if r[3]=='ONLINE' else ('y' if r[3]=='REVOKED' else 'r')
        h+='<tr><td>'+str(r[0])+'</td><td>'+str(r[1])+':'+str(r[2])+'</td><td class="'+cls+'">'+str(r[3])+'</td><td>'+str(r[4] or '')+'</td><td>'+str(r[5] or '')+'</td><td style="font-size:11px;color:#8b949e">'+(str(r[6] or ''))+'</td></tr>'
    h+='</table>'
    return jsonify({'code':0,'html':h})

@app.route('/admin/api/user_add',methods=['POST'])
@admin_required
def x_uadd():
    d=request.get_json(force=True); u=d.get('username',''); p=d.get('password','')
    if not u or len(p)<6: return jsonify({'code':-1,'msg':'invalid'})
    if db_one("SELECT 1 FROM users WHERE username=%s",(u,)): return jsonify({'code':-1,'msg':'exists'})
    db_exec("INSERT INTO users (username,password_hash) VALUES (%s,%s)",(u,hash_pw(p)))
    return jsonify({'code':0})

@app.route('/admin/api/user_toggle',methods=['POST'])
@admin_required
def x_utog():
    d=request.get_json(force=True); db_exec("UPDATE users SET status=%s WHERE id=%s AND is_admin=0",(d['status'],d['user_id']))
    return jsonify({'code':0})

@app.route('/admin/api/user_del',methods=['POST'])
@admin_required
def x_udel():
    d=request.get_json(force=True); uid=d['user_id']
    db_exec("DELETE FROM user_module_permissions WHERE user_id=%s",(uid,))
    db_exec("DELETE FROM user_accounts WHERE user_id=%s",(uid,))
    db_exec("DELETE FROM users WHERE id=%s AND is_admin=0",(uid,))
    return jsonify({'code':0})

@app.route('/admin/api/account_add',methods=['POST'])
@admin_required
def x_aadd():
    d=request.get_json(force=True); db_exec("INSERT INTO tq_accounts (account_name,tq_username,tq_password) VALUES (%s,%s,%s)",(d['name'],d['user'],d['pass']))
    return jsonify({'code':0})

@app.route('/admin/api/account_toggle',methods=['POST'])
@admin_required
def x_atog():
    d=request.get_json(force=True); db_exec("UPDATE tq_accounts SET status=%s WHERE id=%s",(d['status'],d['id']))
    return jsonify({'code':0})

@app.route('/admin/api/perm_toggle',methods=['POST'])
@admin_required
def x_ptog():
    d=request.get_json(force=True); uid,mid,v=d['user_id'],d['module_id'],d['value']
    if v: db_exec("INSERT IGNORE INTO user_module_permissions (user_id,module_id) VALUES (%s,%s)",(uid,mid))
    else: db_exec("DELETE FROM user_module_permissions WHERE user_id=%s AND module_id=%s",(uid,mid))
    return jsonify({'code':0})

@app.route('/admin/api/assign_account',methods=['POST'])
@admin_required
def x_assacct():
    d=request.get_json(force=True); db_exec("INSERT IGNORE INTO user_accounts (user_id,account_id) VALUES (%s,%s)",(d['user_id'],d['account_id']))
    return jsonify({'code':0})

@app.route('/admin/api/unassign_account',methods=['POST'])
@admin_required
def x_unass():
    d=request.get_json(force=True); db_exec("DELETE FROM user_accounts WHERE user_id=%s AND account_id=%s",(d['user_id'],d['account_id']))
    return jsonify({'code':0})

def main():
    print("="*50); print("  stock_main v3.0 - iframe直连"); print("  Port:",CENTER_PORT); print("="*50)
    init_db()
    threading.Thread(target=hb,daemon=True).start()
    print("[HB] started")
    app.run(host='0.0.0.0',port=CENTER_PORT,debug=False,use_reloader=False)

if __name__=='__main__':
    main()