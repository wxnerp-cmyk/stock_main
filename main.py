"""
stock_main v2.0 - 路由主服务 + 安全校验 + 权限模块 + API网关
功能: 用户登录/注册 | 天勤账户管理 | 模块权限 | 服务注册 | 心跳检测 | 反向代理
端口: 9000
"""
import threading, time, uuid, hashlib, secrets, requests
from datetime import datetime
from flask import Flask, request, jsonify, Response, session, redirect, url_for
import pymysql

# ========== 配置 ==========
DB_CONFIG = {
    'host': '192.168.0.106', 'port': 3304,
    'user': 'zhq', 'password': 'zhq1',
    'database': 'd_lnx_tqhq'
}
CENTER_PORT = 9000
HEARTBEAT_INTERVAL = 10
HEARTBEAT_TIMEOUT = 30
MAX_HEARTBEAT_FAILS = 3
SECRET_KEY = secrets.token_hex(32)

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ========== 数据库 ==========
def get_db():
    return pymysql.connect(**DB_CONFIG)

def db_execute(sql, params=()):
    conn = get_db(); cur = conn.cursor()
    cur.execute(sql, params); conn.commit()
    result = cur.fetchall() if cur.description else []
    conn.close(); return result

def db_one(sql, params=()):
    rows = db_execute(sql, params); return rows[0] if rows else None

def init_db():
    conn = pymysql.connect(**DB_CONFIG); cur = conn.cursor()
    
    cur.execute('''CREATE TABLE IF NOT EXISTS service_registry (
        id INT AUTO_INCREMENT PRIMARY KEY,
        service_name VARCHAR(100) UNIQUE NOT NULL,
        host VARCHAR(50) NOT NULL, port INT NOT NULL,
        service_token VARCHAR(64) NOT NULL,
        routes TEXT,
        status ENUM('ONLINE','OFFLINE','REVOKED') DEFAULT 'ONLINE',
        last_heartbeat DATETIME NULL, register_time DATETIME NULL,
        heartbeat_fail_count INT DEFAULT 0
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')

    cur.execute('''CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(128) NOT NULL,
        is_admin TINYINT DEFAULT 0,
        status TINYINT DEFAULT 1,
        create_time DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')

    cur.execute('''CREATE TABLE IF NOT EXISTS tq_accounts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        account_name VARCHAR(100) NOT NULL COMMENT '账户别名',
        tq_username VARCHAR(100) NOT NULL COMMENT '天勤用户名',
        tq_password VARCHAR(100) NOT NULL COMMENT '天勤密码',
        status TINYINT DEFAULT 1,
        create_time DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')

    cur.execute('''CREATE TABLE IF NOT EXISTS modules (
        id INT AUTO_INCREMENT PRIMARY KEY,
        module_name VARCHAR(100) NOT NULL COMMENT '模块名称(前端显示)',
        module_key VARCHAR(50) UNIQUE NOT NULL COMMENT '模块标识(quotes/kline/expiry)',
        service_name VARCHAR(100) NOT NULL COMMENT '对应的子服务名',
        route_path VARCHAR(200) NOT NULL COMMENT '子服务的路由路径',
        icon VARCHAR(10) DEFAULT '📊',
        sort_order INT DEFAULT 0,
        status TINYINT DEFAULT 1
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')

    cur.execute('''CREATE TABLE IF NOT EXISTS user_accounts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        account_id INT NOT NULL,
        UNIQUE KEY uk_ua (user_id, account_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')

    cur.execute('''CREATE TABLE IF NOT EXISTS user_module_permissions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        module_id INT NOT NULL,
        UNIQUE KEY uk_um (user_id, module_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')

    # 初始化默认数据
    if not db_one("SELECT 1 FROM users WHERE username='admin'"):
        pw = hashlib.sha256('admin123'.encode()).hexdigest()
        cur.execute("INSERT INTO users (username,password_hash,is_admin) VALUES ('admin',%s,1)", (pw,))
    if not db_one("SELECT 1 FROM tq_accounts"):
        cur.execute("INSERT INTO tq_accounts (account_name,tq_username,tq_password) VALUES ('猪八戒','zhubajie','jinhu303')")
    if not db_one("SELECT 1 FROM modules"):
        cur.execute("INSERT INTO modules (module_name,module_key,service_name,route_path,icon,sort_order) VALUES "
                    "('行情看板','quotes','stock-app-01','/',%s,1),"
                    "('K线图','kline','stock-app-01','/api/kline',%s,2),"
                    "('到期表','expiry','stock-app-01','/option-expiry',%s,3)",
                    ('📈','📉','📅'))
    
    conn.commit(); conn.close()
    print("[DB] 所有表就绪 (service_registry + users + tq_accounts + modules + user_accounts + user_module_permissions)")

# ========== 工具函数 ==========
def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

def login_required(f):
    from functools import wraps
    @wraps(f)
    def wrap(*a, **kw):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*a, **kw)
    return wrap

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def wrap(*a, **kw):
        if 'user_id' not in session: return redirect(url_for('login_page'))
        if not session.get('is_admin'): return '<h3>无权限</h3>', 403
        return f(*a, **kw)
    return wrap

def api_login_required(f):
    from functools import wraps
    @wraps(f)
    def wrap(*a, **kw):
        if 'user_id' not in session: return jsonify({'code':-1,'msg':'未登录'}), 401
        return f(*a, **kw)
    return wrap

def get_user_modules(user_id):
    """获取用户可访问的模块列表(含服务信息)"""
    if session.get('is_admin'):
        rows = db_execute("SELECT module_name,module_key,service_name,route_path,icon FROM modules WHERE status=1 ORDER BY sort_order")
    else:
        rows = db_execute(
            "SELECT m.module_name,m.module_key,m.service_name,m.route_path,m.icon "
            "FROM modules m JOIN user_module_permissions p ON m.id=p.module_id "
            "WHERE p.user_id=%s AND m.status=1 ORDER BY m.sort_order", (user_id,))
    return [{'name':r[0],'key':r[1],'service':r[2],'route':r[3],'icon':r[4]} for r in rows]

def get_user_accounts(user_id):
    """获取用户已分配的账户列表"""
    rows = db_execute(
        "SELECT a.id,a.account_name,a.tq_username FROM tq_accounts a "
        "JOIN user_accounts ua ON a.id=ua.account_id WHERE ua.user_id=%s AND a.status=1", (user_id,))
    return [{'id':r[0],'name':r[1],'username':r[2]} for r in rows]

# ========== 心跳检测 ==========
def heartbeat_checker():
    while True:
        try:
            rows = db_execute("SELECT service_name,host,port,service_token,heartbeat_fail_count FROM service_registry WHERE status='ONLINE'")
            for name, host, port, token, fail_count in rows:
                try:
                    resp = requests.get(f"http://{host}:{port}/health", params={'token':token}, timeout=5)
                    if resp.status_code==200 and resp.json().get('alive'):
                        db_execute("UPDATE service_registry SET last_heartbeat=%s,heartbeat_fail_count=0 WHERE service_name=%s", (datetime.now(),name))
                    else: fail_count+=1; _hf(name,fail_count)
                except: fail_count+=1; _hf(name,fail_count)
        except Exception as e: print(f"[心跳] {e}")
        time.sleep(HEARTBEAT_INTERVAL)

def _hf(name,fc):
    if fc>=MAX_HEARTBEAT_FAILS:
        db_execute("UPDATE service_registry SET status='OFFLINE',heartbeat_fail_count=%s WHERE service_name=%s",(fc,name))
        print(f"[心跳] {name} OFFLINE")
    else: db_execute("UPDATE service_registry SET heartbeat_fail_count=%s WHERE service_name=%s",(fc,name))

# ========== 注册接口(保持兼容) ==========
@app.route('/register', methods=['POST'])
def api_register():
    data = request.get_json(force=True)
    for f in ['service_name','host','port']:
        if f not in data: return jsonify({'code':-1,'msg':'missing '+f}), 400
    sn,h,p = data['service_name'],data['host'],data['port']
    routes = data.get('routes','')
    token = str(uuid.uuid4())
    try:
        if db_one("SELECT 1 FROM service_registry WHERE service_name=%s",(sn,)):
            db_execute("UPDATE service_registry SET host=%s,port=%s,service_token=%s,routes=%s,status='ONLINE',last_heartbeat=%s,heartbeat_fail_count=0 WHERE service_name=%s",(h,p,token,routes,datetime.now(),sn))
        else:
            db_execute("INSERT INTO service_registry (service_name,host,port,service_token,routes) VALUES (%s,%s,%s,%s,%s)",(sn,h,p,token,routes))
    except Exception as e: return jsonify({'code':-1,'msg':str(e)}),500
    return jsonify({'code':0,'service_token':token,'heartbeat_interval':HEARTBEAT_INTERVAL})

@app.route('/unregister', methods=['POST'])
def api_unregister():
    t = request.get_json(force=True).get('service_token','')
    if t: db_execute("UPDATE service_registry SET status='OFFLINE' WHERE service_token=%s",(t,))
    return jsonify({'code':0})

@app.route('/health')
def health(): return jsonify({'alive':True,'service':'stock_main'})

# ========== 登录/注册页面 ==========
LOGIN_HTML = '''<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><title>登录</title>
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
<div class="box"><h2>📈 行情系统</h2>
<div class="error" id="err"></div>
<input id="u" placeholder="用户名"><input id="p" type="password" placeholder="密码">
<button class="btn" onclick="login()">登 录</button>
<button class="btn btn2" onclick="register()">注册新用户</button>
<div class="tip">默认管理员: admin / admin123</div>
</div><script>
function login(){fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})}).then(r=>r.json()).then(d=>{if(d.code==0)location.href='/app';else document.getElementById('err').textContent=d.msg})}
function register(){var u=document.getElementById('u').value,p=document.getElementById('p').value;if(!u||!p){document.getElementById('err').textContent='请填写用户名和密码';return}if(p.length<6){document.getElementById('err').textContent='密码至少6位';return}fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})}).then(r=>r.json()).then(d=>{if(d.code==0){document.getElementById('err').textContent='注册成功,请登录';document.getElementById('err').style.color='#26a641'}else document.getElementById('err').textContent=d.msg})}
</script></body></html>'''

@app.route('/login')
def login_page():
    if 'user_id' in session: return redirect('/app')
    return LOGIN_HTML

@app.route('/')
def root(): return redirect('/login')

@app.route('/api/login', methods=['POST'])
def api_login():
    d = request.get_json(force=True)
    u,p = d.get('username',''), hash_pw(d.get('password',''))
    row = db_one("SELECT id,is_admin FROM users WHERE username=%s AND password_hash=%s AND status=1",(u,p))
    if not row: return jsonify({'code':-1,'msg':'用户名或密码错误'})
    session['user_id']=row[0]; session['username']=u; session['is_admin']=bool(row[1])
    # 默认选择第一个账户
    accts = get_user_accounts(row[0])
    if accts: session['current_account_id']=accts[0]['id']; session['current_account_name']=accts[0]['name']
    return jsonify({'code':0,'is_admin':bool(row[1])})

@app.route('/api/register', methods=['POST'])
def api_user_register():
    d = request.get_json(force=True)
    u,p = d.get('username',''), d.get('password','')
    if not u or len(p)<6: return jsonify({'code':-1,'msg':'用户名不能为空,密码至少6位'})
    if db_one("SELECT 1 FROM users WHERE username=%s",(u,)): return jsonify({'code':-1,'msg':'用户名已存在'})
    db_execute("INSERT INTO users (username,password_hash) VALUES (%s,%s)",(u,hash_pw(p)))
    return jsonify({'code':0,'msg':'注册成功'})

@app.route('/logout')
def logout():
    session.clear(); return redirect('/login')

# ========== 主应用框架 ==========
@app.route('/app')
@login_required
def app_main():
    modules = get_user_accounts(session['user_id'])
    # modules = get_user_modules(session['user_id'])
    # 这里用 session 的 username 和 account 信息渲染
    return render_main_shell()

def render_main_shell():
    cur_acct = session.get('current_account_name','未分配账户')
    accts = get_user_accounts(session['user_id'])
    mods = get_user_modules(session['user_id'])
    is_admin = session.get('is_admin', False)
    
    # 账户选项
    acct_opts = ''.join(f'<option value="{a["id"]}" {"selected" if str(a["id"])==str(session.get("current_account_id","")) else ""}>{a["name"]} ({a["username"]})</option>' for a in accts)
    
    # 模块导航
    nav_items = ''.join(f'<a href="#" class="nav-item" onclick="switchModule(\'{m["key"]}\',\'{m["route"]}\')" data-key="{m["key"]}"><span>{m["icon"]}</span> {m["name"]}</a>' for m in mods)
    
    return f'''<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><title>行情系统</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Microsoft YaHei',sans-serif;background:#0d1117;color:#c9d1d9;display:flex;height:100vh;overflow:hidden}}
/* 侧边栏 */
.sidebar{{width:200px;background:#161b22;border-right:1px solid #30363d;display:flex;flex-direction:column}}
.sidebar-header{{padding:16px;border-bottom:1px solid #30363d}}
.sidebar-header h3{{color:#58a6ff;font-size:15px}}
.sidebar-nav{{flex:1;padding:8px}}
.nav-item{{display:flex;align-items:center;gap:8px;padding:10px 12px;color:#8b949e;text-decoration:none;border-radius:6px;margin-bottom:4px;font-size:13px;transition:all .2s}}
.nav-item:hover{{background:#1c2129;color:#c9d1d9}}
.nav-item.active{{background:#1f6feb22;color:#58a6ff;border-left:3px solid #58a6ff}}
/* 内容区 */
.main{{flex:1;display:flex;flex-direction:column}}
.topbar{{height:48px;background:#161b22;border-bottom:1px solid #30363d;display:flex;align-items:center;justify-content:space-between;padding:0 16px}}
.topbar-left{{display:flex;align-items:center;gap:12px}}
.topbar-right{{display:flex;align-items:center;gap:12px;font-size:13px}}
.topbar select{{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;padding:4px 8px;font-size:12px}}
.topbar .user{{color:#58a6ff}}
.topbar a{{color:#f85149;text-decoration:none;font-size:12px}}
.content{{flex:1;overflow:auto;padding:0}}
.content iframe{{width:100%;height:100%;border:none}}
.admin-link{{color:#f0c000!important;font-size:12px}}
</style></head><body>
<div class="sidebar">
  <div class="sidebar-header"><h3>📈 行情系统</h3><p style="font-size:11px;color:#8b949e">{session.get("username","")}</p></div>
  <div class="sidebar-nav">{nav_items}
    {f'<a href="/admin" class="nav-item" style="color:#f0c000">⚙️ 管理后台</a>' if is_admin else ''}
  </div>
</div>
<div class="main">
  <div class="topbar">
    <div class="topbar-left"><b style="color:#58a6ff">📊 路由中心</b></div>
    <div class="topbar-right">
      <span>账户:</span>
      <select id="acctSelect" onchange="switchAccount()">{acct_opts}</select>
      <span class="user">👤 {session.get("username","")}</span>
      <a href="/logout">退出</a>
    </div>
  </div>
  <div class="content"><iframe id="contentFrame" src="/api/gw/quotes/?tq_acct={cur_acct}"></iframe></div>
</div>
<script>
var currentModule='quotes',currentRoute='/';
function switchModule(key,route){{currentModule=key;currentRoute=route;document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));document.querySelector('[data-key="'+key+'"]').classList.add('active');loadContent()}}
function loadContent(){{
  var select=document.getElementById('acctSelect');
  var acctName=select.options[select.selectedIndex]?.text.split(' (')[0]||'';
  var gwUrl='/api/gw/'+currentModule+currentRoute+'?tq_acct='+encodeURIComponent(acctName);
  // 对于根路由('/')，用特殊前缀; 对于API路由，直接拼接
  var iframe=document.getElementById('contentFrame');
  if(currentRoute==='/'){{gwUrl='/api/gw/'+currentModule+'/?tq_acct='+encodeURIComponent(acctName)}}
  iframe.src=gwUrl;
}}
function switchAccount(){{
  var select=document.getElementById('acctSelect');
  var acctId=select.value, acctName=select.options[select.selectedIndex]?.text.split(' (')[0]||'';
  fetch('/api/account/switch',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{account_id:parseInt(acctId),account_name:acctName}})}}).then(r=>r.json()).then(d=>{{if(d.code==0)loadContent()}});
}}
// 初始状态
document.querySelector('[data-key="quotes"]')?.classList?.add('active');
</script></body></html>'''

@app.route('/api/account/switch', methods=['POST'])
@api_login_required
def api_switch_account():
    d = request.get_json(force=True)
    session['current_account_id'] = d['account_id']
    session['current_account_name'] = d['account_name']
    return jsonify({'code':0})

# ========== API 网关 ==========
@app.route('/api/gw/<module_key>/', defaults={'sub_path': ''}, methods=['GET','POST'])
@app.route('/api/gw/<module_key>/<path:sub_path>', methods=['GET','POST'])
@login_required
def api_gateway(module_key, sub_path):
    """API网关: 查找模块对应的子服务并转发请求"""
    # 权限校验
    user_id = session['user_id']
    if not session.get('is_admin'):
        perm = db_one("SELECT 1 FROM user_module_permissions p JOIN modules m ON p.module_id=m.id WHERE p.user_id=%s AND m.module_key=%s", (user_id, module_key))
        if not perm:
            return jsonify({'code':-1,'msg':'无此模块访问权限'}), 403
    
    mod = db_one("SELECT service_name,route_path FROM modules WHERE module_key=%s AND status=1", (module_key,))
    if not mod: return jsonify({'code':-1,'msg':'模块不存在'}), 404
    
    svc = db_one("SELECT host,port FROM service_registry WHERE service_name=%s AND status='ONLINE'", (mod[0],))
    if not svc: return jsonify({'code':-1,'msg':'模块服务不在线'}), 503
    
    host, port = svc
    target_path = mod[1] if not sub_path else mod[1].rstrip('/') + '/' + sub_path
    target_url = f"http://{host}:{port}{target_path}"
    
    # 转发参数 + 天勤账户信息
    params = {k:v for k,v in request.args.items()}
    acct_id = session.get('current_account_id')
    if acct_id:
        acct = db_one("SELECT tq_username,tq_password FROM tq_accounts WHERE id=%s",(acct_id,))
        if acct:
            params['tq_user'] = acct[0]
            params['tq_pass'] = acct[1]
    
    if params: target_url += '?' + ('&'.join(f'{k}={v}' for k,v in params.items()))
    
    try:
        if request.method=='POST':
            resp = requests.post(target_url, json=request.get_json(silent=True) or {}, timeout=60)
        else:
            resp = requests.get(target_url, timeout=60)
        return Response(resp.content, status=resp.status_code,
                       content_type=resp.headers.get('content-type','text/html'))
    except Exception as e:
        return jsonify({'code':-1,'msg':f'转发失败:{e}'}), 502

# ========== 管理后台 ==========
@app.route('/admin')
@admin_required
def admin_panel():
    return render_admin_html()

def render_admin_html():
    return '''<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><title>管理后台</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Microsoft YaHei',sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}
h1{color:#58a6ff;margin-bottom:20px}
.tabs{display:flex;gap:8px;margin-bottom:20px}
.tab{padding:8px 20px;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#8b949e;cursor:pointer;font-size:13px}
.tab:hover{color:#c9d1d9}
.tab.active{background:#1f6feb22;border-color:#58a6ff;color:#58a6ff}
.panel{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:12px}
th{background:#0d1117;padding:8px 12px;text-align:left;border-bottom:2px solid #30363d;color:#58a6ff}
td{padding:6px 12px;border-bottom:1px solid #21262d}
button,.btn{padding:4px 12px;border-radius:4px;border:1px solid #30363d;background:#21262d;color:#c9d1d9;cursor:pointer;font-size:12px;margin:2px}
button:hover{background:#30363d}
.btn-danger{color:#f85149;border-color:#f85149}
input,select{padding:6px 10px;border-radius:4px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;font-size:12px;margin:2px}
.form-row{display:flex;gap:8px;align-items:center;margin-bottom:12px;flex-wrap:wrap}
.green{color:#26a641}.red{color:#f85149}.yellow{color:#f0c000}
</style></head><body>
<h1>⚙️ 管理后台</h1>
<div class="tabs">
  <button class="tab active" onclick="showTab('users')">用户管理</button>
  <button class="tab" onclick="showTab('accounts')">天勤账户</button>
  <button class="tab" onclick="showTab('modules')">模块权限</button>
  <button class="tab" onclick="showTab('services')">服务状态</button>
</div>
<div id="panel" class="panel">加载中...</div>
<script>
var curTab='users';
function showTab(t){curTab=t;document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active'));event.target.classList.add('active');loadTab()}
function loadTab(){fetch('/admin/api/'+curTab).then(r=>r.json()).then(d=>{document.getElementById('panel').innerHTML=d.html})}
function api(url,data,cb){fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data||{})}).then(r=>r.json()).then(cb)}
loadTab();
</script></body></html>'''

# 管理API
@app.route('/admin/api/users')
@admin_required
def admin_users():
    rows = db_execute("SELECT id,username,is_admin,status,create_time FROM users ORDER BY id")
    h = '<div class="form-row"><input id="newUser" placeholder="用户名"><input id="newPw" type="password" placeholder="密码"><button onclick="addUser()">新增</button></div><table><tr><th>ID</th><th>用户名</th><th>管理员</th><th>状态</th><th>创建时间</th><th>操作</th></tr>'
    for r in rows:
        h += f'<tr><td>{r[0]}</td><td>{r[1]}</td><td>{"✓" if r[2] else ""}</td><td class="{"green" if r[3] else "red"}">{"正常" if r[3] else "禁用"}</td><td>{r[4]}</td><td>'
        if not r[2]: h += f'<button onclick="toggleUser({r[0]},{0 if r[3] else 1})">{"禁用" if r[3] else "启用"}</button>'
        h += f'<button class="btn-danger" onclick="delUser({r[0]})">删除</button></td></tr>'
    h += '</table>'
    h += '''<script>function addUser(){var u=document.getElementById('newUser').value,p=document.getElementById('newPw').value;api('/admin/api/user_add',{username:u,password:p},function(d){if(d.code==0)loadTab();else alert(d.msg)})}
    function toggleUser(id,s){api('/admin/api/user_toggle',{user_id:id,status:s},loadTab)}
    function delUser(id){if(confirm('确定删除?'))api('/admin/api/user_del',{user_id:id},loadTab)}</script>'''
    return jsonify({'code':0,'html':h})

@app.route('/admin/api/accounts')
@admin_required
def admin_accounts():
    rows = db_execute("SELECT id,account_name,tq_username,status FROM tq_accounts ORDER BY id")
    h = '<div class="form-row"><input id="accName" placeholder="账户别名"><input id="accUser" placeholder="天勤用户名"><input id="accPw" type="password" placeholder="天勤密码"><button onclick="addAcc()">新增</button></div><table><tr><th>ID</th><th>别名</th><th>天勤账号</th><th>状态</th><th>操作</th></tr>'
    for r in rows:
        h += f'<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td class="{"green" if r[3] else "red"}">{"正常" if r[3] else "禁用"}</td><td><button onclick="toggleAcc({r[0]},{0 if r[3] else 1})">{"禁用" if r[3] else "启用"}</button></td></tr>'
    h += '</table><script>function addAcc(){api("/admin/api/account_add",{name:document.getElementById("accName").value,user:document.getElementById("accUser").value,pass:document.getElementById("accPw").value},loadTab)}function toggleAcc(id,s){api("/admin/api/account_toggle",{id:id,status:s},loadTab)}</script>'
    return jsonify({'code':0,'html':h})

@app.route('/admin/api/modules')
@admin_required
def admin_modules():
    users = db_execute("SELECT id,username FROM users WHERE status=1 ORDER BY id")
    mods = db_execute("SELECT id,module_name,module_key FROM modules WHERE status=1 ORDER BY sort_order")
    opts = ''.join('<option value="{}">{}</option>'.format(u[0], u[1]) for u in users)
    h = '<div class="form-row"><select id="permUser"><option value="">选择用户</option>' + opts + '</select><button onclick="loadPerm()">查看权限</button></div><div id="permResult"></div>'
    h += '''<script>function loadPerm(){var uid=document.getElementById("permUser").value;if(!uid)return;fetch("/admin/api/user_perms?user_id="+uid).then(r=>r.json()).then(d=>{document.getElementById("permResult").innerHTML=d.html})}</script>'''
    return jsonify({'code':0,'html':h})

@app.route('/admin/api/user_perms')
@admin_required
def admin_user_perms():
    uid = request.args.get('user_id','')
    if not uid: return jsonify({'html':''})
    mods = db_execute("SELECT id,module_name,module_key FROM modules WHERE status=1 ORDER BY sort_order")
    user_perms = {r[0] for r in db_execute("SELECT module_id FROM user_module_permissions WHERE user_id=%s",(uid,))}
    h = '<table><tr><th>模块</th><th>状态</th><th>操作</th></tr>'
    for mid, mn, mk in mods:
        has = mid in user_perms
        h += f'<tr><td>{mn} ({mk})</td><td class="{"green" if has else "red"}">{"✓ 允许" if has else "✗ 禁止"}</td><td><button onclick="togglePerm({uid},{mid},{0 if has else 1})">{"禁止" if has else "允许"}</button></td></tr>'
    h += '</table>'
    h += f'''<hr><div class="form-row"><b>分配账户给此用户:</b><select id="acctSelect"><option value="">选择账户</option>{"".join(f"<option value='{a[0]}'>{a[1]} ({a[2]})</option>" for a in db_execute('SELECT id,account_name,tq_username FROM tq_accounts WHERE status=1'))}</select><button onclick="assignAcct({uid})">分配</button></div><div id="acctList"></div>'''
    h += '''<script>function togglePerm(uid,mid,v){api("/admin/api/perm_toggle",{user_id:uid,module_id:mid,value:v},function(){loadPerm()})}
    function assignAcct(uid){var aid=document.getElementById("acctSelect").value;if(!aid)return;api("/admin/api/assign_account",{user_id:uid,account_id:parseInt(aid)},function(){loadPerm()})}
    fetch("/admin/api/user_accounts?user_id="+'''+uid+''').then(r=>r.json()).then(d=>{document.getElementById("acctList").innerHTML=d.html})</script>'''
    return jsonify({'code':0,'html':h})

@app.route('/admin/api/user_accounts')
@admin_required
def admin_user_accounts():
    uid = request.args.get('user_id','')
    rows = db_execute("SELECT a.id,a.account_name,a.tq_username FROM tq_accounts a JOIN user_accounts ua ON a.id=ua.account_id WHERE ua.user_id=%s",(uid,))
    h = '<table><tr><th>账户ID</th><th>别名</th><th>天勤账号</th><th>操作</th></tr>'
    for r in rows:
        h += f'<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td><button class="btn-danger" onclick="unassign({uid},{r[0]})">移除</button></td></tr>'
    h += '</table><script>function unassign(uid,aid){api("/admin/api/unassign_account",{user_id:uid,account_id:aid},function(){loadPerm()})}</script>'
    return jsonify({'code':0,'html':h})

@app.route('/admin/api/services')
@admin_required
def admin_services():
    rows = db_execute("SELECT service_name,host,port,status,last_heartbeat,heartbeat_fail_count,routes FROM service_registry ORDER BY register_time DESC")
    h = '<table><tr><th>服务名</th><th>地址</th><th>状态</th><th>最后心跳</th><th>失败次数</th><th>路由</th></tr>'
    for r in rows:
        cls = 'green' if r[3]=='ONLINE' else ('yellow' if r[3]=='REVOKED' else 'red')
        h += f'<tr><td>{r[0]}</td><td>{r[1]}:{r[2]}</td><td class="{cls}">{r[3]}</td><td>{r[4]}</td><td>{r[5]}</td><td style="font-size:11px;color:#8b949e">{r[6] or ""}</td></tr>'
    h += '</table>'
    return jsonify({'code':0,'html':h})

# 管理操作API
@app.route('/admin/api/user_add', methods=['POST'])
@admin_required
def user_add():
    d = request.get_json(force=True)
    u,p = d.get('username',''), d.get('password','')
    if not u or len(p)<6: return jsonify({'code':-1,'msg':'参数错误'})
    if db_one("SELECT 1 FROM users WHERE username=%s",(u,)): return jsonify({'code':-1,'msg':'用户名已存在'})
    db_execute("INSERT INTO users (username,password_hash) VALUES (%s,%s)",(u,hash_pw(p)))
    return jsonify({'code':0})

@app.route('/admin/api/user_toggle', methods=['POST'])
@admin_required
def user_toggle():
    d = request.get_json(force=True)
    db_execute("UPDATE users SET status=%s WHERE id=%s AND is_admin=0",(d['status'],d['user_id']))
    return jsonify({'code':0})

@app.route('/admin/api/user_del', methods=['POST'])
@admin_required
def user_del():
    d = request.get_json(force=True)
    db_execute("DELETE FROM user_module_permissions WHERE user_id=%s",(d['user_id'],))
    db_execute("DELETE FROM user_accounts WHERE user_id=%s",(d['user_id'],))
    db_execute("DELETE FROM users WHERE id=%s AND is_admin=0",(d['user_id'],))
    return jsonify({'code':0})

@app.route('/admin/api/account_add', methods=['POST'])
@admin_required
def account_add():
    d = request.get_json(force=True)
    db_execute("INSERT INTO tq_accounts (account_name,tq_username,tq_password) VALUES (%s,%s,%s)",(d['name'],d['user'],d['pass']))
    return jsonify({'code':0})

@app.route('/admin/api/account_toggle', methods=['POST'])
@admin_required
def account_toggle():
    d = request.get_json(force=True)
    db_execute("UPDATE tq_accounts SET status=%s WHERE id=%s",(d['status'],d['id']))
    return jsonify({'code':0})

@app.route('/admin/api/perm_toggle', methods=['POST'])
@admin_required
def perm_toggle():
    d = request.get_json(force=True)
    uid,mid,v = d['user_id'],d['module_id'],d['value']
    if v:
        try: db_execute("INSERT IGNORE INTO user_module_permissions (user_id,module_id) VALUES (%s,%s)",(uid,mid))
        except: pass
    else:
        db_execute("DELETE FROM user_module_permissions WHERE user_id=%s AND module_id=%s",(uid,mid))
    return jsonify({'code':0})

@app.route('/admin/api/assign_account', methods=['POST'])
@admin_required
def assign_account():
    d = request.get_json(force=True)
    try: db_execute("INSERT IGNORE INTO user_accounts (user_id,account_id) VALUES (%s,%s)",(d['user_id'],d['account_id']))
    except: pass
    return jsonify({'code':0})

@app.route('/admin/api/unassign_account', methods=['POST'])
@admin_required
def unassign_account():
    d = request.get_json(force=True)
    db_execute("DELETE FROM user_accounts WHERE user_id=%s AND account_id=%s",(d['user_id'],d['account_id']))
    return jsonify({'code':0})

# ========== 启动 ==========
def main():
    print("="*50)
    print("  stock_main v2.0 - 路由+安全+权限+网关")
    print(f"  端口: {CENTER_PORT}")
    print("="*50)
    init_db()
    threading.Thread(target=heartbeat_checker, daemon=True).start()
    print(f"[心跳] 已启动 (间隔{HEARTBEAT_INTERVAL}s)")
    app.run(host='0.0.0.0', port=CENTER_PORT, debug=False, use_reloader=False)

if __name__ == '__main__':
    main()