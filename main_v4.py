"""
stock_main v4.0 - RBAC权限体系 + 模块权限 + 数据隔离
功能: 用户登录/注册 | 角色管理 | 模块权限(角色+个人) | 天勤账户分配 | 服务注册 | 心跳检测 | API网关
端口: 9000
"""
import threading, time, uuid, hashlib, secrets, requests, base64, os, hmac, json
from cryptography.fernet import Fernet
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
import queue as _queue
_DB_POOL = _queue.Queue(maxsize=16)

class _DbPooled:
    """连接池包装：close() 归还池中而非真正断开；其余属性/方法透传底层连接。"""
    def __init__(self, conn): self._c = conn
    def __getattr__(self, name): return getattr(self._c, name)
    def close(self): _return_db(self._c)
    def ping(self, reconnect=True): return self._c.ping(reconnect=reconnect)
    @property
    def open(self): return getattr(self._c, "open", False)

def _return_db(conn):
    try:
        if getattr(conn, "open", False):
            _DB_POOL.put_nowait(conn); return
    except Exception: pass
    try: conn.close()
    except Exception: pass

def get_db():
    """从连接池取一个可用连接(自动探活), 池空则新建。调用方照常 conn.close() 即可归还。"""
    try:
        conn = _DB_POOL.get_nowait()
        if conn is not None and getattr(conn, "open", False):
            try:
                conn.ping(reconnect=True)
                return _DbPooled(conn)
            except Exception: pass
    except _queue.Empty: pass
    return _DbPooled(pymysql.connect(**DB_CONFIG))

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
        heartbeat_fail_count INT DEFAULT 0,
        gw_secret VARCHAR(64) DEFAULT ''
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')
    # 兼容已存在的旧表(无 gw_secret 列)
    try:
        cur.execute("ALTER TABLE service_registry ADD COLUMN gw_secret VARCHAR(64) DEFAULT ''")
    except Exception:
        pass

    cur.execute('''CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(128) NOT NULL,
        is_admin TINYINT DEFAULT 0,
        status TINYINT DEFAULT 1,
        create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')

    cur.execute('''CREATE TABLE IF NOT EXISTS tq_accounts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        account_name VARCHAR(100) NOT NULL COMMENT '账户别名',
        tq_username VARCHAR(100) NOT NULL COMMENT '天勤用户名',
        tq_password VARCHAR(100) NOT NULL COMMENT '天勤密码',
        status TINYINT DEFAULT 1,
        create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')

    cur.execute('''CREATE TABLE IF NOT EXISTS modules (
        id INT AUTO_INCREMENT PRIMARY KEY,
        module_name VARCHAR(100) NOT NULL COMMENT '模块名称',
        module_key VARCHAR(50) UNIQUE NOT NULL COMMENT '模块标识',
        service_name VARCHAR(100) NOT NULL COMMENT '对应子服务名',
        route_path VARCHAR(200) NOT NULL COMMENT '子服务路由路径',
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

    # ===== v4.0 新增: 角色体系 =====
    cur.execute('''CREATE TABLE IF NOT EXISTS roles (
        id INT AUTO_INCREMENT PRIMARY KEY,
        role_name VARCHAR(50) UNIQUE NOT NULL COMMENT '角色名称',
        role_key VARCHAR(50) UNIQUE NOT NULL COMMENT '角色标识(admin/trader/viewer)',
        description VARCHAR(200) DEFAULT '',
        is_system TINYINT DEFAULT 0 COMMENT '系统预置角色不可删除',
        status TINYINT DEFAULT 1,
        create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')

    cur.execute('''CREATE TABLE IF NOT EXISTS role_permissions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        role_id INT NOT NULL,
        module_id INT NOT NULL,
        perm_level ENUM('view','use','admin') DEFAULT 'use' COMMENT 'view=只读 use=操作 admin=管理',
        UNIQUE KEY uk_rm (role_id, module_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')

    cur.execute('''CREATE TABLE IF NOT EXISTS user_roles (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        role_id INT NOT NULL,
        UNIQUE KEY uk_ur (user_id, role_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')

    # ===== 初始化默认数据 =====
    if not db_one("SELECT 1 FROM users WHERE username='admin'"):
        pw = hashlib.sha256('admin123'.encode()).hexdigest()
        cur.execute("INSERT INTO users (username,password_hash,is_admin) VALUES ('admin',%s,1)", (pw,))
    if not db_one("SELECT 1 FROM tq_accounts"):
        cur.execute("INSERT INTO tq_accounts (account_name,tq_username,tq_password) VALUES ('猪八戒','zhubajie',%s)", (encrypt_secret('jinhu303'),))
    if not db_one("SELECT 1 FROM modules"):
        cur.execute("INSERT INTO modules (module_name,module_key,service_name,route_path,icon,sort_order) VALUES "
                    "('行情看板','quotes','stock-app-01','/',%s,1),"
                    "('K线图','kline','stock-app-01','/api/kline',%s,2),"
                    "('期货到期表','expiry','stock-app-01','/option-expiry',%s,3)",
                    ('📈','📉','📅'))
    # 初始化角色
    if not db_one("SELECT 1 FROM roles"):
        cur.execute("INSERT INTO roles (role_name,role_key,description,is_system) VALUES "
                    "('管理员','admin','系统管理员,拥有全部权限',1),"
                    "('交易员','trader','可查看行情和K线,执行交易操作',1),"
                    "('观察者','viewer','仅可查看行情,无操作权限',1)")
        mods = db_execute("SELECT id FROM modules WHERE status=1")
        for m in mods:
            cur.execute("INSERT INTO role_permissions (role_id,module_id,perm_level) VALUES (1,%s,'admin')", (m[0],))
        mod_map = {r[2]: r[0] for r in db_execute("SELECT id,module_name,module_key FROM modules")}
        if 'quotes' in mod_map: cur.execute("INSERT INTO role_permissions (role_id,module_id,perm_level) VALUES (2,%s,'use')", (mod_map['quotes'],))
        if 'kline' in mod_map: cur.execute("INSERT INTO role_permissions (role_id,module_id,perm_level) VALUES (2,%s,'use')", (mod_map['kline'],))
        if 'expiry' in mod_map: cur.execute("INSERT INTO role_permissions (role_id,module_id,perm_level) VALUES (2,%s,'view')", (mod_map['expiry'],))
        if 'quotes' in mod_map: cur.execute("INSERT INTO role_permissions (role_id,module_id,perm_level) VALUES (3,%s,'view')", (mod_map['quotes'],))

    # 清理历史残留: 早期误加的 algo 模块(属其他开发者, 不应在此注册) — 幂等删除已存在的行
    _algo_old = db_one("SELECT id FROM modules WHERE module_key='algo'")
    if _algo_old:
        cur.execute("DELETE FROM role_permissions WHERE module_id=%s", (_algo_old[0],))
        cur.execute("DELETE FROM modules WHERE id=%s", (_algo_old[0],))

    # ===== 期权日历模块(options): 从原"到期表"拆出为独立 module_key, 各自服务 =====
    # 1) 原 expiry 模块改名"期货到期表"(兼容旧库里仍叫"到期表"的行)
    _ex = db_one("SELECT id, module_name FROM modules WHERE module_key='expiry'")
    if _ex and _ex[1] != '期货到期表':
        cur.execute("UPDATE modules SET module_name='期货到期表' WHERE module_key='expiry'")
    # 2) 新增独立的期权日历模块(仅期权, route=/options-calendar)
    if not db_one("SELECT 1 FROM modules WHERE module_key='options'"):
        cur.execute("INSERT INTO modules (module_name,module_key,service_name,route_path,icon,sort_order) VALUES ('期权日历','options','stock-app-01','/options-calendar','🗓️',5)")
    _opt_id = db_one("SELECT id FROM modules WHERE module_key='options'")
    if _opt_id:
        for _rid, _lvl in [(1, 'admin'), (2, 'use'), (3, 'view')]:
            if not db_one("SELECT 1 FROM role_permissions WHERE role_id=%s AND module_id=%s", (_rid, _opt_id[0])):
                cur.execute("INSERT INTO role_permissions (role_id,module_id,perm_level) VALUES (%s,%s,%s)", (_rid, _opt_id[0], _lvl))

    # ===== 期权模块(optchain): 独立"期权"一级模块, 目录首页 + T型报价, 与期权日历并列 =====
    if not db_one("SELECT 1 FROM modules WHERE module_key='optchain'"):
        cur.execute("INSERT INTO modules (module_name,module_key,service_name,route_path,icon,sort_order) VALUES ('期权','optchain','stock-app-01','/optchain','📊',4)")
    _oc_id = db_one("SELECT id FROM modules WHERE module_key='optchain'")
    if _oc_id:
        for _rid, _lvl in [(1, 'admin'), (2, 'use'), (3, 'view')]:
            if not db_one("SELECT 1 FROM role_permissions WHERE role_id=%s AND module_id=%s", (_rid, _oc_id[0])):
                cur.execute("INSERT INTO role_permissions (role_id,module_id,perm_level) VALUES (%s,%s,%s)", (_rid, _oc_id[0], _lvl))

    # 数据同步模块(sync): 给日历页面"同步期货/期权"按钮用, 不在侧边栏显示
    if not db_one("SELECT 1 FROM modules WHERE module_key='sync'"):
        cur.execute("INSERT INTO modules (module_name,module_key,service_name,route_path,icon,sort_order,status) VALUES ('数据同步','sync','stock-app-01','/api/sync','🔄',6,1)")
    _sync_id = db_one("SELECT id FROM modules WHERE module_key='sync'")
    if _sync_id:
        for _rid, _lvl in [(1, 'admin'), (2, 'use'), (3, 'view')]:
            if not db_one("SELECT 1 FROM role_permissions WHERE role_id=%s AND module_id=%s", (_rid, _sync_id[0])):
                cur.execute("INSERT INTO role_permissions (role_id,module_id,perm_level) VALUES (%s,%s,%s)", (_rid, _sync_id[0], _lvl))

    # ===== 短线量化模块(shortquant): 独立"短线量化"模块 =====
    if not db_one("SELECT 1 FROM modules WHERE module_key='shortquant'"):
        cur.execute("INSERT INTO modules (module_name,module_key,service_name,route_path,icon,sort_order,status) VALUES ('短线量化','shortquant','stock-app-01','/shortquant','⚡',8,1)")
    _sq_id = db_one("SELECT id FROM modules WHERE module_key='shortquant'")
    if _sq_id:
        for _rid, _lvl in [(1, 'admin'), (2, 'use'), (3, 'view')]:
            if not db_one("SELECT 1 FROM role_permissions WHERE role_id=%s AND module_id=%s", (_rid, _sq_id[0])):
                cur.execute("INSERT INTO role_permissions (role_id,module_id,perm_level) VALUES (%s,%s,%s)", (_rid, _sq_id[0], _lvl))

    # ===== 期货K线模块(futureskline): 独立"期货K线"模块, K线图 + 周期切换 =====
    if not db_one("SELECT 1 FROM modules WHERE module_key='futureskline'"):
        cur.execute("INSERT INTO modules (module_name,module_key,service_name,route_path,icon,sort_order,status) VALUES ('期货K线','futureskline','stock-app-01','/futureskline','🕯️',9,1)")
    _fk_id = db_one("SELECT id FROM modules WHERE module_key='futureskline'")
    if _fk_id:
        for _rid, _lvl in [(1, 'admin'), (2, 'use'), (3, 'view')]:
            if not db_one("SELECT 1 FROM role_permissions WHERE role_id=%s AND module_id=%s", (_rid, _fk_id[0])):
                cur.execute("INSERT INTO role_permissions (role_id,module_id,perm_level) VALUES (%s,%s,%s)", (_rid, _fk_id[0], _lvl))

    # ===== 股票模块(stockkline): 独立"股票"模块, 全部A股列表 + 周/月MACD金叉 =====
    if not db_one("SELECT 1 FROM modules WHERE module_key='stockkline'"):
        cur.execute("INSERT INTO modules (module_name,module_key,service_name,route_path,icon,sort_order,status) VALUES ('股票','stockkline','stock-app-01','/stockkline','📈',11,1)")
    _sk_id = db_one("SELECT id FROM modules WHERE module_key='stockkline'")
    if _sk_id:
        for _rid, _lvl in [(1, 'admin'), (2, 'use'), (3, 'view')]:
            if not db_one("SELECT 1 FROM role_permissions WHERE role_id=%s AND module_id=%s", (_rid, _sk_id[0])):
                cur.execute("INSERT INTO role_permissions (role_id,module_id,perm_level) VALUES (%s,%s,%s)", (_rid, _sk_id[0], _lvl))

    conn.commit(); conn.close()
    print("[DB] 所有表就绪 (9张: 注册+用户+账户+模块+用户账户+用户权限+角色+角色权限+用户角色)")

# ========== 工具函数 ==========
def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

# ========== 天勤密码可逆加密 (Fernet) ==========
def _fernet_key():
    raw = os.environ.get('TQ_PASS_KEY') or 'stock-dev-default-passkey-change-me'
    return base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest())

_fernet = Fernet(_fernet_key())

def encrypt_secret(plain: str) -> str:
    if not plain: return ''
    return _fernet.encrypt(plain.encode()).decode()

def decrypt_secret(cipher: str) -> str:
    if not cipher: return ''
    try:
        return _fernet.decrypt(cipher.encode()).decode()
    except Exception:
        return cipher  # 已是明文(迁移前)

def is_encrypted(v: str) -> bool:
    if not v: return False
    try:
        _fernet.decrypt(v.encode()); return True
    except Exception:
        return False

def migrate_tq_passwords():
    """将历史明文天勤密码转为密文(幂等)"""
    for rid, pw in db_execute("SELECT id,tq_password FROM tq_accounts"):
        if pw and not is_encrypted(pw):
            db_execute("UPDATE tq_accounts SET tq_password=%s WHERE id=%s", (encrypt_secret(pw), rid))
    print("[迁移] 天勤密码明文->密文 完成")

# ========== 网关身份令牌 (HMAC, 按 service 专属 gw_secret 签名) ==========
def make_gw_token(user_id, username, module_key, service_name, gw_secret, ttl=60):
    payload = {
        'uid': user_id, 'uname': username, 'mod': module_key,
        'aud': service_name, 'exp': int(time.time()) + ttl,
        'n': secrets.token_hex(8)
    }
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    sig = hmac.new(gw_secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"

def _user_is_active(user_id):
    """实时查询用户是否仍然有效(status=1)。用于禁用用户后立即生效。"""
    row = db_one("SELECT status FROM users WHERE id=%s", (user_id,))
    return row is not None and row[0] == 1

def _logout_response():
    """清除 session 并返回登录页重定向（兼容顶层页面和 iframe 请求）。"""
    session.clear()
    return redirect(url_for('login_page'))

def login_required(f):
    from functools import wraps
    @wraps(f)
    def wrap(*a, **kw):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        if not _user_is_active(session['user_id']):
            return _logout_response()
        return f(*a, **kw)
    return wrap

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def wrap(*a, **kw):
        if 'user_id' not in session: return redirect(url_for('login_page'))
        if not _user_is_active(session['user_id']):
            return _logout_response()
        if not session.get('is_admin'): return '<h3>无权限</h3>', 403
        return f(*a, **kw)
    return wrap

def api_login_required(f):
    from functools import wraps
    @wraps(f)
    def wrap(*a, **kw):
        if 'user_id' not in session: return jsonify({'code':-1,'msg':'未登录'}), 401
        if not _user_is_active(session['user_id']):
            session.clear()
            return jsonify({'code':-1,'msg':'用户已被禁用或删除'}), 403
        return f(*a, **kw)
    return wrap


# ========== v4.0 核心: 权限计算 ==========

def get_user_permissions(user_id):
    LEVEL_ORDER = {'view': 1, 'use': 2, 'admin': 3}
    if session.get('is_admin'):
        modules = db_execute("SELECT module_key FROM modules WHERE status=1")
        return {m[0]: 'admin' for m in modules}

    perms = {}
    role_perms = db_execute(
        "SELECT m.module_key, rp.perm_level FROM role_permissions rp "
        "JOIN modules m ON rp.module_id=m.id "
        "JOIN user_roles ur ON rp.role_id=ur.role_id "
        "WHERE ur.user_id=%s AND m.status=1", (user_id,))
    for mk, lv in role_perms:
        perms[mk] = max(perms.get(mk, 'view'), lv, key=lambda x: LEVEL_ORDER.get(x, 0))

    personal = db_execute(
        "SELECT m.module_key FROM user_module_permissions up "
        "JOIN modules m ON up.module_id=m.id "
        "WHERE up.user_id=%s AND m.status=1", (user_id,))
    for mk in personal:
        if mk not in perms:
            perms[mk] = 'use'
    return perms

def get_user_modules(user_id):
    perms = get_user_permissions(user_id)
    if not perms:
        return []
    module_keys = list(perms.keys())
    all_modules = db_execute(
        "SELECT module_name,module_key,service_name,route_path,icon FROM modules "
        "WHERE module_key IN (" + ','.join(['%s']*len(module_keys)) + ") AND module_key NOT IN ('sync','kline') AND status=1 ORDER BY sort_order",
        module_keys)
    result = []
    for r in all_modules:
        result.append({
            'name': r[0], 'key': r[1], 'service': r[2],
            'route': r[3], 'icon': r[4],
            'perm_level': perms.get(r[1], 'view')
        })
    return result

def check_module_permission(user_id, module_key, required_level='view'):
    perms = get_user_permissions(user_id)
    if module_key not in perms:
        return False
    LEVEL_ORDER = {'view': 1, 'use': 2, 'admin': 3}
    return LEVEL_ORDER.get(perms[module_key], 0) >= LEVEL_ORDER.get(required_level, 0)

def get_user_accounts(user_id):
    rows = db_execute(
        "SELECT a.id,a.account_name,a.tq_username FROM tq_accounts a "
        "JOIN user_accounts ua ON a.id=ua.account_id WHERE ua.user_id=%s AND a.status=1", (user_id,))
    return [{'id':r[0],'name':r[1],'username':r[2]} for r in rows]

# ========== 心跳检测 ==========
def heartbeat_checker():
    while True:
        try:
            # 检测所有已注册服务，OFFLINE 服务恢复后也能自动恢复 ONLINE
            rows = db_execute("SELECT service_name,host,port,service_token,heartbeat_fail_count,status FROM service_registry")
            for name, host, port, token, fail_count, status in rows:
                try:
                    resp = requests.get(f"http://{host}:{port}/health", params={'token':token}, timeout=5)
                    if resp.status_code==200 and resp.json().get('alive'):
                        if status != 'ONLINE' or fail_count != 0:
                            db_execute("UPDATE service_registry SET status='ONLINE',last_heartbeat=%s,heartbeat_fail_count=0 WHERE service_name=%s", (datetime.now(),name))
                            print(f"[心跳] {name} 恢复 ONLINE")
                        else:
                            db_execute("UPDATE service_registry SET last_heartbeat=%s WHERE service_name=%s", (datetime.now(),name))
                    else:
                        fail_count+=1; _hf(name,fail_count)
                except Exception:
                    fail_count+=1; _hf(name,fail_count)
        except Exception as e: print(f"[心跳] {e}")
        time.sleep(HEARTBEAT_INTERVAL)

def _hf(name,fc):
    if fc>=MAX_HEARTBEAT_FAILS:
        db_execute("UPDATE service_registry SET status='OFFLINE',heartbeat_fail_count=%s WHERE service_name=%s",(fc,name))
        print(f"[心跳] {name} OFFLINE")
    else: db_execute("UPDATE service_registry SET heartbeat_fail_count=%s WHERE service_name=%s",(fc,name))

# ========== 注册接口 ==========
@app.route('/register', methods=['POST'])
def api_register():
    data = request.get_json(force=True)
    for f in ['service_name','host','port']:
        if f not in data: return jsonify({'code':-1,'msg':'missing '+f}), 400
    sn,h,p = data['service_name'],data['host'],data['port']
    routes = data.get('routes','')
    token = str(uuid.uuid4())
    gw_secret = secrets.token_hex(32)
    try:
        if db_one("SELECT 1 FROM service_registry WHERE service_name=%s",(sn,)):
            db_execute("UPDATE service_registry SET host=%s,port=%s,service_token=%s,routes=%s,gw_secret=%s,status='ONLINE',last_heartbeat=%s,heartbeat_fail_count=0 WHERE service_name=%s",(h,p,token,routes,gw_secret,datetime.now(),sn))
        else:
            db_execute("INSERT INTO service_registry (service_name,host,port,service_token,routes,gw_secret) VALUES (%s,%s,%s,%s,%s,%s)",(sn,h,p,token,routes,gw_secret))
    except Exception as e: return jsonify({'code':-1,'msg':str(e)}),500
    return jsonify({'code':0,'service_token':token,'gw_secret':gw_secret,'heartbeat_interval':HEARTBEAT_INTERVAL})

@app.route('/unregister', methods=['POST'])
def api_unregister():
    t = request.get_json(force=True).get('service_token','')
    if t: db_execute("UPDATE service_registry SET status='OFFLINE' WHERE service_token=%s",(t,))
    return jsonify({'code':0})

@app.route('/health')
def health(): return jsonify({'alive':True,'service':'stock_main_v4'})

# ========== 登录/注册页面 ==========
LOGIN_HTML = '''<!DOCTYPE html>
<html lang="zh"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>登录 - 行情系统</title>
<style>
:root{--bg:#0b1120;--surface:#161e2e;--surface2:#1b2538;--border:#27344b;--text:#e6edf7;--muted:#94a3b8;--accent:#38bdf8;--violet:#c084fc;--shadow:0 18px 50px rgba(0,0,0,.5)}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Microsoft YaHei','PingFang SC',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;background:radial-gradient(900px 500px at 78% -10%,rgba(56,189,248,.18),transparent),radial-gradient(700px 400px at 12% 110%,rgba(192,132,252,.16),transparent),linear-gradient(160deg,#0b1120,#0d1526);color:var(--text)}
.box{width:440px;max-width:100%;background:linear-gradient(180deg,var(--surface),var(--surface2));border:1px solid var(--border);border-radius:20px;padding:40px 36px;box-shadow:var(--shadow);animation:pop .5s ease both}
@keyframes pop{from{opacity:0;transform:translateY(14px) scale(.98)}to{opacity:1;transform:none}}
.logo{width:64px;height:64px;border-radius:18px;margin:0 auto 18px;background:linear-gradient(135deg,var(--accent),var(--violet));display:flex;align-items:center;justify-content:center;font-size:34px;box-shadow:0 8px 22px rgba(56,189,248,.45)}
h2{text-align:center;font-size:27px;font-weight:800;margin-bottom:4px;background:linear-gradient(135deg,#7dd3fc,#c084fc);-webkit-background-clip:text;background-clip:text;color:transparent}
.ver{text-align:center;font-size:13px;color:var(--muted);margin-bottom:24px;letter-spacing:1px}
input{width:100%;padding:15px 16px;margin-bottom:14px;border-radius:12px;border:1px solid var(--border);background:#0d1626;color:var(--text);font-size:18px;transition:.2s}
input::placeholder{color:#5b6b85}
input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(56,189,248,.18)}
.btn{width:100%;padding:16px;border-radius:12px;border:none;background:linear-gradient(135deg,var(--accent),var(--violet));color:#08111f;font-size:20px;font-weight:800;cursor:pointer;margin-bottom:12px;box-shadow:0 8px 20px rgba(56,189,248,.35);transition:.2s}
.btn:hover{filter:brightness(1.08);transform:translateY(-1px)}
.btn2{background:transparent;border:1px solid var(--border);color:var(--text);font-weight:600;box-shadow:none}
.btn2:hover{background:var(--surface2);border-color:var(--accent)}
.error{color:#ff8a8a;font-size:15px;margin-bottom:10px;text-align:center;min-height:18px}
.tip{text-align:center;font-size:14px;color:var(--muted);margin-top:16px;line-height:1.7}
@media(max-width:768px){.box{width:100%;padding:32px 22px}h2{font-size:24px}input{font-size:18px;padding:15px}.btn{font-size:18px;padding:15px}}
</style></head><body>
<div class="box">
  <div class="logo">📈</div>
  <h2>行情系统</h2>
  <div class="ver">v4.0 · RBAC 权限中心</div>
  <div class="error" id="err"></div>
  <input id="u" placeholder="用户名">
  <input id="p" type="password" placeholder="密码">
  <button class="btn" onclick="login()">登 录</button>
  <button class="btn btn2" onclick="register()">注册新用户</button>
  <div class="tip">默认账号<br>admin / admin123 · trader / trader123 · viewer / viewer123</div>
</div>
<script>
if(window.self!==window.top){window.top.location.href='/login';}
function login(){fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})}).then(r=>r.json()).then(d=>{if(d.code==0)window.top.location.href='/app';else document.getElementById('err').textContent=d.msg})}
function register(){var u=document.getElementById('u').value,p=document.getElementById('p').value;if(!u||!p){document.getElementById('err').textContent='请填写用户名和密码';return}if(p.length<6){document.getElementById('err').textContent='密码至少6位';return}fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})}).then(r=>r.json()).then(d=>{if(d.code==0){document.getElementById('err').textContent='注册成功,请登录';document.getElementById('err').style.color='#4ade80'}else document.getElementById('err').textContent=d.msg})}
</script></body></html>
'''

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
    viewer_role = db_one("SELECT id FROM roles WHERE role_key='viewer'")
    if viewer_role:
        new_user_row = db_one("SELECT id FROM users WHERE username=%s",(u,))
        if new_user_row:
            db_execute("INSERT IGNORE INTO user_roles (user_id,role_id) VALUES (%s,%s)",(new_user_row[0], viewer_role[0]))
    return jsonify({'code':0,'msg':'注册成功'})

@app.route('/logout')
def logout():
    session.clear(); return redirect('/login')

# ========== 主应用框架 ==========
@app.route('/app')
@login_required
def app_main():
    return render_main_shell()

SHELL_TEMPLATE = r'''<!DOCTYPE html>
<html lang="zh"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>行情系统 v4.0</title>
<style>
:root{
  --bg:#0b1120; --surface:#161e2e; --surface2:#1b2538; --border:#27344b;
  --text:#e6edf7; --muted:#94a3b8; --accent:#38bdf8; --violet:#c084fc;
  --shadow:0 10px 30px rgba(0,0,0,.38);
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Microsoft YaHei','PingFang SC',sans-serif;background:linear-gradient(160deg,#0b1120,#0d1526);color:var(--text);display:flex;height:100vh;overflow:hidden;font-size:18px}
.sidebar{width:250px;min-width:250px;background:linear-gradient(180deg,var(--surface),#101827);border-right:1px solid var(--border);display:flex;flex-direction:column;transition:width .25s ease,min-width .25s ease,opacity .2s ease,padding .2s;box-shadow:4px 0 24px rgba(0,0,0,.3);z-index:100;overflow:hidden}
.sidebar.collapsed{width:0;min-width:0;padding:0;opacity:0;border-right-color:transparent}
.sidebar .sidebar-inner{min-width:250px;opacity:1;transition:opacity .2s}
.sidebar.collapsed .sidebar-inner{opacity:0}
.sidebar-header{padding:20px 18px;border-bottom:1px solid var(--border)}
.brand{display:flex;align-items:center;gap:12px}
.logo{width:42px;height:42px;border-radius:12px;background:linear-gradient(135deg,var(--accent),var(--violet));display:flex;align-items:center;justify-content:center;font-size:24px;box-shadow:0 6px 16px rgba(56,189,248,.4)}
.ttl{font-size:22px;font-weight:800;background:linear-gradient(135deg,#7dd3fc,#c084fc);-webkit-background-clip:text;background-clip:text;color:transparent}
.ver{font-size:12px;color:var(--muted);letter-spacing:1px}
.user-pill{margin-top:14px;display:inline-flex;align-items:center;gap:8px;padding:8px 14px;border-radius:20px;background:#0d1626;border:1px solid var(--border);font-size:15px;color:var(--text)}
.sidebar-nav{flex:1;padding:12px;overflow-y:auto}
.nav-item{display:flex;align-items:center;gap:12px;padding:15px 18px;color:var(--muted);text-decoration:none;border-radius:12px;margin-bottom:6px;font-size:18px;font-weight:600;transition:.2s}
.nav-item:hover{background:var(--surface2);color:var(--text);transform:translateX(2px)}
.nav-item.active{background:linear-gradient(135deg,rgba(56,189,248,.18),rgba(192,132,252,.18));color:var(--accent);border-left:4px solid var(--accent)}
.main{flex:1;display:flex;flex-direction:column;min-width:0}
.topbar{height:60px;background:linear-gradient(135deg,rgba(22,30,46,.95),rgba(13,21,38,.95));border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;padding:0 20px;gap:10px;backdrop-filter:blur(8px)}
.topbar-left{display:flex;align-items:center;gap:14px;min-width:0}
.menu-btn{display:none;background:linear-gradient(135deg,var(--accent),var(--violet));color:#08111f;border:none;border-radius:10px;padding:9px 13px;font-size:20px;cursor:pointer}
.collapse-btn{display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:10px;background:linear-gradient(135deg,var(--accent),var(--violet));color:#08111f;border:none;cursor:pointer;font-size:18px;margin-right:8px;transition:transform .2s}
.topbar-title{color:var(--accent);font-size:21px;font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.topbar-right{display:flex;align-items:center;gap:14px;font-size:16px;flex-shrink:0}
.topbar .lbl{color:var(--muted)}
.topbar select{background:#0d1626;color:var(--text);border:1px solid var(--border);border-radius:10px;padding:9px 12px;font-size:15px;max-width:150px;cursor:pointer}
.topbar select:focus{outline:none;border-color:var(--accent)}
.logout{color:#ff8a8a;text-decoration:none;font-size:15px;font-weight:600;padding:8px 14px;border-radius:10px;border:1px solid rgba(255,138,138,.3);transition:.2s}
.logout:hover{background:rgba(255,138,138,.12)}
.content{flex:1;overflow:auto;padding:0}
.content iframe{width:100%;height:100%;border:none;display:block;background:#0b1120}
.mask{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:90}
@media(max-width:1024px){
  body{font-size:20px}
  .menu-btn{display:inline-block}
  .collapse-btn{display:none}
  .sidebar{position:fixed;left:0;top:0;bottom:0;transform:translateX(-100%);width:260px;min-width:260px;opacity:1;padding:0}
  .sidebar.open{transform:translateX(0)}
  .sidebar.collapsed{transform:translateX(-100%);width:260px;min-width:260px}
  .mask.show{display:block}
  .topbar{height:66px;padding:0 14px}
  .topbar-title{font-size:22px}
  .topbar-right{font-size:18px;gap:10px}
  .topbar select{font-size:17px;padding:10px;max-width:130px}
  .nav-item{font-size:20px;padding:18px 20px}
  .ttl{font-size:24px}
}
@media(max-width:480px){
  .topbar-right .lbl{display:none}
  .topbar select{max-width:110px}
}
</style></head><body>
<div class="mask" id="mask" onclick="toggleMenu()"></div>
<div class="sidebar" id="sidebar">
  <div class="sidebar-header">
    <div class="brand"><span class="logo">📈</span><div><div class="ttl">行情系统</div><div class="ver">v4.0 · RBAC</div></div></div>
    <div class="user-pill">👤 __USERNAME__</div>
  </div>
  <div class="sidebar-nav">__NAV_ITEMS__
    __ADMIN_LINK__
  </div>
</div>
<div class="main">
  <div class="topbar">
    <div class="topbar-left">
      <button class="menu-btn" onclick="toggleMenu()" aria-label="菜单">☰</button>
      <button class="collapse-btn" onclick="toggleSidebar()" title="收起侧边栏" aria-label="收起侧边栏">◀</button>
      <b class="topbar-title">📊 路由中心</b>
    </div>
    <div class="topbar-right">
      <span class="lbl">账户</span>
      <select id="acctSelect" onchange="switchAccount()">__ACCT_OPTS__</select>
      <a href="/logout" class="logout">退出</a>
    </div>
  </div>
  <div class="content"><iframe id="contentFrame" src="/api/gw/quotes/?tq_acct=__CUR_ACCT__"></iframe></div>
</div>
<script>
var currentModule='quotes',currentRoute='/';
function switchModule(key,route){currentModule=key;currentRoute=route;document.querySelectorAll('.nav-item').forEach(function(n){n.classList.remove('active');});document.querySelector('[data-key="'+key+'"]').classList.add('active');loadContent();}
function loadContent(){
  if(currentModule==='admin'){document.getElementById('contentFrame').src='/admin';return;}
  var select=document.getElementById('acctSelect');
  var acctName=(select.options[select.selectedIndex]?select.options[select.selectedIndex].text.split(' (')[0]:'')||'';
  var gwUrl='/api/gw/'+currentModule+'/?tq_acct='+encodeURIComponent(acctName);
  if(currentRoute!=='/')gwUrl='/api/gw/'+currentModule+currentRoute+'?tq_acct='+encodeURIComponent(acctName);
  document.getElementById('contentFrame').src=gwUrl;
}
function switchAccount(){
  var select=document.getElementById('acctSelect');
  var acctId=select.value, acctName=(select.options[select.selectedIndex]?select.options[select.selectedIndex].text.split(' (')[0]:'')||'';
  fetch('/api/account/switch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({account_id:parseInt(acctId),account_name:acctName})}).then(function(r){return r.json();}).then(function(d){if(d.code==0)loadContent();});
}
document.querySelector('[data-key="quotes"]')?.classList?.add('active');
function toggleMenu(){var s=document.getElementById('sidebar'),m=document.getElementById('mask');s.classList.toggle('open');m.classList.toggle('show');}
function toggleSidebar(){
  var s=document.getElementById('sidebar');
  s.classList.toggle('collapsed');
  var collapsed=s.classList.contains('collapsed');
  document.querySelectorAll('.collapse-btn').forEach(function(b){b.textContent=collapsed?'▶':'◀';b.title=collapsed?'展开侧边栏':'收起侧边栏';});
  try{localStorage.setItem('sidebarCollapsed', collapsed?'1':'0');}catch(e){}
}
function restoreSidebar(){
  var s=document.getElementById('sidebar');
  if(!s) return;
  var v='0';
  try{v=localStorage.getItem('sidebarCollapsed')||'0';}catch(e){}
  if(v==='1' && window.innerWidth>1024){
    s.classList.add('collapsed');
    document.querySelectorAll('.collapse-btn').forEach(function(b){b.textContent='▶';b.title='展开侧边栏';});
  } else {
    s.classList.remove('collapsed');
  }
}
window.addEventListener('resize',function(){
  var s=document.getElementById('sidebar'),m=document.getElementById('mask');
  if(window.innerWidth>1024){
    s.classList.remove('open');
    m.classList.remove('show');
    restoreSidebar();
  } else {
    s.classList.remove('collapsed');
  }
});
restoreSidebar();
setInterval(function(){
  fetch('/api/me').then(function(r){if(!r.ok){window.top.location.href='/login';return;}return r.json();}).then(function(d){if(!d||d.code!==0){window.top.location.href='/login';}}).catch(function(){window.top.location.href='/login';});
},15000);
</script></body></html>
'''

def render_main_shell():
    cur_acct = session.get('current_account_name','未分配账户')
    is_admin = session.get('is_admin', False)
    # 账户下拉: 管理员可见全部账户(可切换任意); 普通用户仅见被授权账户(已隔离)
    if is_admin:
        accts = [{'id': r[0], 'name': r[1], 'username': r[2]} for r in
                 db_execute("SELECT id,account_name,tq_username FROM tq_accounts WHERE status=1")]
    else:
        accts = get_user_accounts(session['user_id'])
    mods = get_user_modules(session['user_id'])

    acct_opts = ''.join(f'<option value="{a["id"]}" {"selected" if str(a["id"])==str(session.get("current_account_id","")) else ""}>{a["name"]} ({a["username"]})</option>' for a in accts)
    nav_items = ''
    for m in mods:
        badge = {'admin':'🛡️','use':'✏️','view':'👁️'}.get(m['perm_level'],'')
        nav_items += f'<a href="#" class="nav-item" onclick="switchModule(\'{m["key"]}\',\'{m["route"]}\')" data-key="{m["key"]}"><span>{m["icon"]}</span> {m["name"]}<span style="font-size:10px;margin-left:auto;opacity:0.5">{badge}</span></a>'
    admin_link = "<a href='#' class='nav-item' data-key='admin' onclick='switchModule(\"admin\",\"/\")' style='color:#f0c000'>⚙️ 管理后台</a>" if is_admin else ''

    return (SHELL_TEMPLATE
            .replace('__USERNAME__', session.get('username',''))
            .replace('__NAV_ITEMS__', nav_items)
            .replace('__ACCT_OPTS__', acct_opts)
            .replace('__ADMIN_LINK__', admin_link)
            .replace('__CUR_ACCT__', cur_acct))

@app.route('/api/me', methods=['GET'])
@api_login_required
def api_me():
    """返回当前登录用户基本信息，供前端心跳检测会话是否仍然有效。"""
    return jsonify({'code': 0, 'user_id': session.get('user_id'), 'username': session.get('username'), 'is_admin': session.get('is_admin', False)})

@app.route('/api/account/switch', methods=['POST'])
@api_login_required
def api_switch_account():
    d = request.get_json(force=True)
    aid = d['account_id']
    # 权限校验: 普通用户只能切换到自己被授权的账户; 管理员可切换任意账户
    if not session.get('is_admin'):
        allowed = {a['id'] for a in get_user_accounts(session['user_id'])}
        if aid not in allowed:
            return jsonify({'code': -1, 'msg': '无权切换到该账户'}), 403
    acct = db_one("SELECT account_name,tq_username FROM tq_accounts WHERE id=%s AND status=1", (aid,))
    if not acct:
        return jsonify({'code': -1, 'msg': '账户不存在或已停用'}), 404
    session['current_account_id'] = aid
    session['current_account_name'] = acct[0]
    return jsonify({'code':0})

# ========== API 网关 (v4.0: 角色权限检查) ==========
@app.route('/api/gw/<module_key>/', defaults={'sub_path': ''}, methods=['GET','POST'])
@app.route('/api/gw/<module_key>/<path:sub_path>', methods=['GET','POST'])
@login_required
def api_gateway(module_key, sub_path):
    user_id = session['user_id']
    if not check_module_permission(user_id, module_key, 'view'):
        return jsonify({'code':-1,'msg':'无此模块访问权限'}), 403

    mod = db_one("SELECT service_name,route_path FROM modules WHERE module_key=%s AND status=1", (module_key,))
    if not mod: return jsonify({'code':-1,'msg':'模块不存在'}), 404

    svc = db_one("SELECT host,port,gw_secret FROM service_registry WHERE service_name=%s AND status='ONLINE'", (mod[0],))
    if not svc: return jsonify({'code':-1,'msg':'模块服务不在线'}), 503

    host, port, gw_secret = svc[0], svc[1], (svc[2] if len(svc) > 2 else '')
    # 构造目标路径: 去除sub_path中已含的route_path前缀, 防止重复拼接
    target_path = mod[1]
    if sub_path:
        route_prefix = mod[1].lstrip('/')
        clean_sub = sub_path
        if route_prefix and clean_sub.startswith(route_prefix):
            clean_sub = clean_sub[len(route_prefix):].lstrip('/')
        if clean_sub:
            target_path = target_path.rstrip('/') + '/' + clean_sub
    target_url = f"http://{host}:{port}{target_path}"

    params = {k:v for k,v in request.args.items()}
    acct_id = session.get('current_account_id')
    if acct_id:
        acct = db_one("SELECT tq_username,tq_password FROM tq_accounts WHERE id=%s",(acct_id,))
        if acct:
            params['tq_user'] = acct[0]
            params['tq_pass'] = decrypt_secret(acct[1])

    if params: target_url += '?' + ('&'.join(f'{k}={v}' for k,v in params.items()))

    # 构造网关身份令牌(用该服务专属 gw_secret 签名), 经 X-Gw-Token 头下发, 供下游 center_client 校验
    gw_token = ''
    if gw_secret:
        gw_token = make_gw_token(user_id, session.get('username',''), module_key, mod[0], gw_secret)
    gw_headers = {'X-Gw-Token': gw_token} if gw_token else {}

    try:
        if request.method=='POST':
            if request.is_json:
                # 下游期望 JSON 的请求(如行情/持仓)原样转发 JSON
                resp = requests.post(target_url, json=request.get_json(silent=True) or {}, headers=gw_headers, timeout=60)
            else:
                # 转发原始 form/urlencoded body(含扫描面板的 rules 表单字段),
                # 保留原始 Content-Type, 否则下游 request.form 解析不到 rules -> 回退 DEFAULT_RULES
                fwd_headers = dict(gw_headers)
                fwd_headers['Content-Type'] = request.headers.get('Content-Type', 'application/x-www-form-urlencoded')
                resp = requests.post(target_url, data=request.get_data(), headers=fwd_headers, timeout=60)
        else:
            resp = requests.get(target_url, headers=gw_headers, timeout=60)
        content_type = resp.headers.get('content-type','text/html')
        body = resp.content
        # HTML响应: 注入CSS隐藏子服务导航 + 改写API路径走网关(避免iframe内跨域)
        if 'text/html' in content_type:
            hide_css = b'<style>h1,nav,.subtitle,.section-title:first-of-type{display:none!important} body{padding-top:8px!important}</style>'
            body = body.replace(b'<head>', b'<head>' + hide_css, 1)
            if b'<head>' not in body:
                body = hide_css + body
            # 改写绝对路径, 让子服务JS的fetch/链接走网关代理
            gw_pfx = f'/api/gw/{module_key}'.encode()
            body = body.replace(b'"/api/', b'"' + gw_pfx + b'/api/')
            body = body.replace(b"'/api/", b"'" + gw_pfx + b"/api/")
            body = body.replace(b'href="/option-expiry"', b'href="' + gw_pfx + b'/option-expiry"')
            body = body.replace(b'href=\'/option-expiry\'', b'href=\'' + gw_pfx + b'/option-expiry\'')
        return Response(body, status=resp.status_code, content_type=content_type)
    except Exception as e:
        return jsonify({'code':-1,'msg':f'转发失败:{e}'}), 502

# ========== v4.0 管理后台 ==========
@app.route('/admin')
@admin_required
def admin_panel():
    return render_admin_html()

def render_admin_html():
    return r'''<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><title>管理后台 v4.0</title>
<style>
:root{--bg:#0b1120;--surface:#161e2e;--surface2:#1b2538;--border:#27344b;--border-soft:#1f2a3d;--text:#e6edf7;--muted:#94a3b8;--accent:#38bdf8;--violet:#c084fc;--up:#ff5b5b;--down:#22c55e;--gold:#fbbf24;--shadow:0 10px 30px rgba(0,0,0,.38);--radius:14px}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Microsoft YaHei','PingFang SC',sans-serif;background:radial-gradient(900px 500px at 80% -10%,rgba(56,189,248,.1),transparent),linear-gradient(160deg,#0b1120,#0d1526);color:var(--text);padding:24px;font-size:17px;line-height:1.65}
.admin-title{color:var(--accent);margin-bottom:4px;font-size:27px;font-weight:800}
.ver{font-size:14px;color:var(--muted);margin-bottom:18px}
.tabs{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap}
.tab{padding:12px 24px;border-radius:10px;border:1px solid var(--border);background:var(--surface);color:var(--muted);cursor:pointer;font-size:16px;font-weight:600;transition:.2s}
.tab:hover{color:var(--text);border-color:var(--accent);transform:translateY(-1px)}
.tab.active{background:linear-gradient(135deg,var(--accent),var(--violet));color:#08111f;border-color:transparent;box-shadow:0 4px 12px rgba(56,189,248,.3)}
.panel{background:linear-gradient(180deg,var(--surface),var(--surface2));border:1px solid var(--border);border-radius:var(--radius);padding:22px;min-height:320px;box-shadow:var(--shadow);animation:fadeUp .4s ease both}
@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
table{width:100%;border-collapse:collapse;font-size:16px;margin-top:14px}
th{background:linear-gradient(180deg,#1b2740,#141d30);padding:12px 14px;text-align:left;border-bottom:1px solid var(--border);color:#9fd4ff;font-weight:700}
td{padding:10px 14px;border-bottom:1px solid var(--border-soft)}
tbody tr:hover{background:#16213a}
button,.btn{padding:9px 16px;border-radius:10px;border:1px solid var(--border);background:var(--surface2);color:var(--text);cursor:pointer;font-size:15px;margin:3px;font-weight:600;transition:.2s}
button:hover{background:#243049;border-color:var(--accent)}
.btn-danger{color:#ff8a8a;border-color:rgba(255,138,138,.4)}
.btn-danger:hover{background:rgba(255,138,138,.12)}
.btn-primary{background:linear-gradient(135deg,var(--accent),var(--violet));color:#08111f;border-color:transparent;font-weight:700}
.btn-primary:hover{filter:brightness(1.08)}
input,select,textarea{padding:10px 14px;border-radius:10px;border:1px solid var(--border);background:#0d1626;color:var(--text);font-size:16px;margin:3px}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(56,189,248,.18)}
textarea{width:320px;height:44px;resize:vertical}
.form-row{display:flex;gap:10px;align-items:center;margin-bottom:14px;flex-wrap:wrap}
.green{color:var(--down)}.red{color:var(--up)}.yellow{color:var(--gold)}.blue{color:var(--accent)}
.badge{display:inline-block;padding:3px 10px;border-radius:6px;font-size:12px;font-weight:700}
.badge-admin{background:rgba(255,91,91,.15);color:#ff8a8a}
.badge-use{background:rgba(56,189,248,.15);color:#7dd3fc}
.badge-view{background:rgba(148,163,184,.15);color:#cbd5e1}
.badge-system{background:rgba(251,191,36,.15);color:var(--gold)}
hr{border:none;border-top:1px solid var(--border);margin:18px 0}
</style></head><body>
<h2 class="admin-title">⚙️ 管理后台</h2><p class="ver">v4.0 · RBAC权限体系</p>
<div class="tabs">
  <button class="tab active" onclick="showTab('users')">👥 用户管理</button>
  <button class="tab" onclick="showTab('roles')">🎭 角色管理</button>
  <button class="tab" onclick="showTab('accounts')">🔑 天勤账户</button>
  <button class="tab" onclick="showTab('modules')">🔐 模块权限</button>
  <button class="tab" onclick="showTab('services')">📡 服务状态</button>
</div>
<div id="panel" class="panel">加载中...</div>
<script>
var curTab='users';
function showTab(t){curTab=t;document.querySelectorAll('.tab').forEach(function(b){b.classList.remove('active')});event.target.classList.add('active');loadTab()}
function loadTab(){fetch('/admin/api/'+curTab).then(function(r){return r.json()}).then(function(d){document.getElementById('panel').innerHTML=d.html})}
function api(url,data,cb){fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data||{})}).then(function(r){return r.json()}).then(cb)}

// === 用户管理 ===
function addUser(){
  var u=document.getElementById('newUser'),p=document.getElementById('newPw');
  if(!u||!p)return;
  api('/admin/api/user_add',{username:u.value,password:p.value},function(d){if(d.code==0)loadTab();else alert(d.msg)})
}
function toggleUser(id,s){api('/admin/api/user_toggle',{user_id:id,status:s},loadTab)}
function delUser(id){if(confirm('确定删除?'))api('/admin/api/user_del',{user_id:id},loadTab)}

// === 角色管理 ===
function addRole(){
  var n=document.getElementById('newRoleName'),k=document.getElementById('newRoleKey'),d=document.getElementById('newRoleDesc');
  if(!n||!k){alert('请填写名称和标识');return}
  api('/admin/api/role_add',{role_name:n.value,role_key:k.value,description:d?d.value:''},function(r){if(r.code==0)loadTab();else alert(r.msg)})
}
function toggleRole(id,s){api('/admin/api/role_toggle',{role_id:id,status:s},loadTab)}
function delRole(id){if(confirm('确定删除此角色?'))api('/admin/api/role_del',{role_id:id},loadTab)}
function editRolePerms(rid){fetch('/admin/api/role_perms?role_id='+rid).then(function(r){return r.json()}).then(function(d){document.getElementById('roleDetail').innerHTML=d.html})}
function setRolePerm(rid,mid){
  var v=document.getElementById('rlv_'+mid).value;
  api('/admin/api/role_perm_set',{role_id:rid,module_id:mid,perm_level:v||null},function(){editRolePerms(rid)})
}
function addUserToRole(rid){
  var uid=document.getElementById('addUserToRole').value;
  if(!uid)return;
  api('/admin/api/role_add_user',{role_id:rid,user_id:parseInt(uid)},function(){editRolePerms(rid)})
}
function removeUserRole(uid,rid){
  if(confirm('确定移除此用户的这个角色?'))api('/admin/api/role_remove_user',{role_id:rid,user_id:uid},function(){editRolePerms(rid)})
}

// === 天勤账户 ===
function addAcc(){
  api('/admin/api/account_add',{name:document.getElementById('accName').value,user:document.getElementById('accUser').value,pass:document.getElementById('accPw').value},loadTab)
}
function toggleAcc(id,s){api('/admin/api/account_toggle',{id:id,status:s},loadTab)}

// === 模块权限 ===
function loadUserPerms(){
  var uid=document.getElementById('permUser').value;
  if(!uid)return;
  fetch('/admin/api/user_perms?user_id='+uid).then(function(r){return r.json()}).then(function(d){document.getElementById('permResult').innerHTML=d.html})
}
function togglePerm(uid,mid,v){api('/admin/api/perm_toggle',{user_id:uid,module_id:mid,value:v},loadUserPerms)}
function toggleUserRole(uid,rid,v){api('/admin/api/user_role_set',{user_id:uid,role_id:rid,value:v},loadUserPerms)}
function toggleAcct(uid,aid,v){api('/admin/api/account_assign',{user_id:uid,account_id:aid,value:v},loadUserPerms)}

loadTab();
</script></body></html>'''

# ---- 管理API: 用户管理 ----
@app.route('/admin/api/users')
@admin_required
def admin_users():
    rows = db_execute("SELECT id,username,is_admin,status,create_time FROM users ORDER BY id")
    h = '<div class="form-row"><input id="newUser" placeholder="用户名"><input id="newPw" type="password" placeholder="密码"><button class="btn-primary" onclick="addUser()">新增</button></div>'
    h += '<table><tr><th>ID</th><th>用户名</th><th>管理员</th><th>状态</th><th>创建时间</th><th>操作</th></tr>'
    for r in rows:
        h += f'<tr><td>{r[0]}</td><td>{r[1]}</td><td>{"✓" if r[2] else ""}</td><td class="{"green" if r[3] else "red"}">{"正常" if r[3] else "禁用"}</td><td>{r[4]}</td><td>'
        if not r[2]: h += f'<button onclick="toggleUser({r[0]},{0 if r[3] else 1})">{"禁用" if r[3] else "启用"}</button>'
        h += f'<button class="btn-danger" onclick="delUser({r[0]})">删除</button></td></tr>'
    h += '</table>'
    return jsonify({'code':0,'html':h})

# ---- 管理API: 角色管理 ----
@app.route('/admin/api/roles')
@admin_required
def admin_roles():
    rows = db_execute("SELECT id,role_name,role_key,description,is_system,status FROM roles ORDER BY is_system DESC, id")
    h = '<div class="form-row"><input id="newRoleName" placeholder="角色名称"><input id="newRoleKey" placeholder="角色标识(英文)"><input id="newRoleDesc" placeholder="描述(可选)"><button class="btn-primary" onclick="addRole()">新增角色</button></div>'
    h += '<table><tr><th>ID</th><th>名称</th><th>标识</th><th>描述</th><th>类型</th><th>状态</th><th>操作</th></tr>'
    for r in rows:
        is_sys = r[4]
        h += f'<tr><td>{r[0]}</td><td>{r[1]}</td><td><code>{r[2]}</code></td><td>{r[3] or "-"}</td>'
        h += '<td><span class="badge badge-system">系统</span></td>' if is_sys else '<td>自定义</td>'
        h += f'<td class="{"green" if r[5] else "red"}">{"启用" if r[5] else "禁用"}</td><td>'
        if not is_sys:
            h += f'<button onclick="toggleRole({r[0]},{0 if r[5] else 1})">{"禁用" if r[5] else "启用"}</button>'
            h += f'<button onclick="editRolePerms({r[0]})">模块权限</button>'
            h += f'<button class="btn-danger" onclick="delRole({r[0]})">删除</button>'
        else:
            h += f'<button onclick="editRolePerms({r[0]})">查看权限</button>'
        h += '</td></tr>'
    h += '</table><hr><div id="roleDetail"></div>'
    return jsonify({'code':0,'html':h})

@app.route('/admin/api/role_perms')
@admin_required
def admin_role_perms():
    rid = request.args.get('role_id','')
    if not rid: return jsonify({'html':''})
    role = db_one("SELECT role_name,role_key FROM roles WHERE id=%s",(rid,))
    if not role: return jsonify({'html':'角色不存在'})
    mods = db_execute("SELECT id,module_name,module_key FROM modules WHERE status=1 ORDER BY sort_order")
    role_perm_map = {}
    for rp in db_execute("SELECT module_id,perm_level FROM role_permissions WHERE role_id=%s",(rid,)):
        role_perm_map[rp[0]] = rp[1]

    h = f'<h4 style="color:#58a6ff">{role[0]} ({role[1]}) - 模块权限</h4>'
    h += '<table><tr><th>模块</th><th>当前权限</th><th>设置</th></tr>'
    for mid, mn, mk in mods:
        cur = role_perm_map.get(mid, '-')
        badge = {'admin':'badge-admin','use':'badge-use','view':'badge-view'}.get(cur,'')
        h += f'<tr><td>{mn} ({mk})</td><td><span class="badge {badge}">{cur}</span></td><td>'
        h += f'<select id="rlv_{mid}" onchange="setRolePerm({rid},{mid})"><option value="">移除</option>'
        for lv in ['view','use','admin']:
            sel = 'selected' if lv==cur else ''
            h += f'<option value="{lv}" {sel}>{lv}</option>'
        h += '</select></td></tr>'
    h += '</table>'

    members = db_execute("SELECT u.id,u.username FROM user_roles ur JOIN users u ON ur.user_id=u.id WHERE ur.role_id=%s AND u.status=1",(rid,))
    h += f'<h4 style="color:#58a6ff;margin-top:16px">角色成员 ({len(members)})</h4>'
    h += '<table><tr><th>用户ID</th><th>用户名</th><th>操作</th></tr>'
    for m in members:
        h += f'<tr><td>{m[0]}</td><td>{m[1]}</td><td><button class="btn-danger" onclick="removeUserRole({m[0]},{rid})">移除此角色</button></td></tr>'
    h += '</table>'

    all_users = db_execute("SELECT id,username FROM users WHERE status=1 AND id NOT IN (SELECT user_id FROM user_roles WHERE role_id=%s)",(rid,))
    if all_users:
        opts = ''.join(f'<option value="{u[0]}">{u[1]}</option>' for u in all_users)
        h += f'<div class="form-row" style="margin-top:12px"><select id="addUserToRole"><option value="">选择用户</option>{opts}</select><button class="btn-primary" onclick="addUserToRole({rid})">添加到此角色</button></div>'

    return jsonify({'code':0,'html':h})

# ---- 管理API: 天勤账户 ----
@app.route('/admin/api/accounts')
@admin_required
def admin_accounts():
    rows = db_execute("SELECT id,account_name,tq_username,status FROM tq_accounts ORDER BY id")
    h = '<div class="form-row"><input id="accName" placeholder="账户别名"><input id="accUser" placeholder="天勤用户名"><input id="accPw" type="password" placeholder="天勤密码"><button class="btn-primary" onclick="addAcc()">新增</button></div>'
    h += '<table><tr><th>ID</th><th>别名</th><th>天勤账号</th><th>状态</th><th>操作</th></tr>'
    for r in rows:
        h += f'<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td class="{"green" if r[3] else "red"}">{"正常" if r[3] else "禁用"}</td><td><button onclick="toggleAcc({r[0]},{0 if r[3] else 1})">{"禁用" if r[3] else "启用"}</button></td></tr>'
    h += '</table>'
    return jsonify({'code':0,'html':h})

# ---- 管理API: 模块权限 ----
@app.route('/admin/api/modules')
@admin_required
def admin_modules():
    users = db_execute("SELECT id,username FROM users WHERE status=1 ORDER BY id")
    opts = ''.join('<option value="{}">{}</option>'.format(u[0], u[1]) for u in users)
    h = '<div class="form-row"><select id="permUser"><option value="">选择用户</option>' + opts + '</select><button class="btn-primary" onclick="loadUserPerms()">查看权限</button></div><div id="permResult"></div>'
    return jsonify({'code':0,'html':h})

@app.route('/admin/api/user_perms')
@admin_required
def admin_user_perms():
    uid = request.args.get('user_id','')
    if not uid: return jsonify({'html':''})

    user = db_one("SELECT username FROM users WHERE id=%s",(uid,))
    uname = user[0] if user else ''

    roles = db_execute("SELECT r.id,r.role_name,r.role_key FROM user_roles ur JOIN roles r ON ur.role_id=r.id WHERE ur.user_id=%s AND r.status=1",(uid,))
    role_tags = ''.join(f'<span class="badge badge-system">{r[1]}</span> ' for r in roles)

    mods = db_execute("SELECT id,module_name,module_key FROM modules WHERE status=1 ORDER BY sort_order")
    user_perms = {r[0] for r in db_execute("SELECT module_id FROM user_module_permissions WHERE user_id=%s",(uid,))}

    effective = get_user_permissions(int(uid))

    h = f'<h4 style="color:#58a6ff">{uname} - 权限详情</h4>'
    h += f'<p style="font-size:12px;color:#8b949e;margin-bottom:8px">角色: {role_tags or "无角色"}</p>'

    h += '<table><tr><th>模块</th><th>角色授权</th><th>个人授权</th><th>最终权限</th><th>操作</th></tr>'
    for mid, mn, mk in mods:
        has_personal = mid in user_perms
        eff_lv = effective.get(mk, '-')
        badge = {'admin':'badge-admin','use':'badge-use','view':'badge-view'}.get(eff_lv,'')
        h += f'<tr><td>{mn} ({mk})</td><td>-</td><td class="{"green" if has_personal else ""}">{"✓ 个人授权" if has_personal else "-"}</td>'
        h += f'<td><span class="badge {badge}">{eff_lv}</span></td>'
        h += f'<td><button onclick="togglePerm({uid},{mid},{0 if has_personal else 1})">{"取消个人授权" if has_personal else "添加个人授权"}</button></td></tr>'
    h += '</table>'

    all_roles = db_execute("SELECT id,role_name,role_key FROM roles WHERE status=1")
    user_role_ids = {r[0] for r in roles}
    h += '<hr><h4 style="color:#58a6ff">角色分配</h4><div class="form-row">'
    for r in all_roles:
        assigned = r[0] in user_role_ids
        cls = 'btn-primary' if assigned else ''
        h += f'<button class="{cls}" onclick="toggleUserRole({uid},{r[0]},{0 if assigned else 1})">{r[1]} {"✓" if assigned else "+"}</button> '
    h += '</div>'

    accts = db_execute("SELECT a.id,a.account_name,a.tq_username FROM tq_accounts a WHERE a.status=1")
    user_acct_ids = {a['id'] for a in get_user_accounts(int(uid))}
    h += '<hr><h4 style="color:#58a6ff">数据权限 - 天勤账户</h4>'
    h += '<table><tr><th>账户</th><th>天勤账号</th><th>已分配</th><th>操作</th></tr>'
    for a in accts:
        has = a[0] in user_acct_ids
        h += f'<tr><td>{a[1]}</td><td>{a[2]}</td><td class="{"green" if has else "red"}">{"✓" if has else "✗"}</td>'
        h += f'<td><button onclick="toggleAcct({uid},{a[0]},{0 if has else 1})">{"移除" if has else "分配"}</button></td></tr>'
    h += '</table>'

    return jsonify({'code':0,'html':h})

# ---- 管理API: 服务状态 ----
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

# ========== 管理操作API ==========

@app.route('/admin/api/user_add', methods=['POST'])
@admin_required
def user_add():
    d = request.get_json(force=True)
    u,p = d.get('username',''), d.get('password','')
    if not u or len(p)<6: return jsonify({'code':-1,'msg':'参数错误'})
    if db_one("SELECT 1 FROM users WHERE username=%s",(u,)): return jsonify({'code':-1,'msg':'用户名已存在'})
    db_execute("INSERT INTO users (username,password_hash) VALUES (%s,%s)",(u,hash_pw(p)))
    new_user_row = db_one("SELECT id FROM users WHERE username=%s",(u,))
    viewer = db_one("SELECT id FROM roles WHERE role_key='viewer'")
    if new_user_row and viewer:
        db_execute("INSERT IGNORE INTO user_roles (user_id,role_id) VALUES (%s,%s)",(new_user_row[0], viewer[0]))
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
    uid = d['user_id']
    db_execute("DELETE FROM user_module_permissions WHERE user_id=%s",(uid,))
    db_execute("DELETE FROM user_accounts WHERE user_id=%s",(uid,))
    db_execute("DELETE FROM user_roles WHERE user_id=%s",(uid,))
    db_execute("DELETE FROM users WHERE id=%s AND is_admin=0",(uid,))
    return jsonify({'code':0})

@app.route('/admin/api/role_add', methods=['POST'])
@admin_required
def role_add():
    d = request.get_json(force=True)
    n,k,desc = d.get('role_name',''), d.get('role_key',''), d.get('description','')
    if not n or not k: return jsonify({'code':-1,'msg':'名称和标识不能为空'})
    if db_one("SELECT 1 FROM roles WHERE role_key=%s",(k,)): return jsonify({'code':-1,'msg':'角色标识已存在'})
    db_execute("INSERT INTO roles (role_name,role_key,description) VALUES (%s,%s,%s)",(n,k,desc))
    return jsonify({'code':0})

@app.route('/admin/api/role_toggle', methods=['POST'])
@admin_required
def role_toggle():
    d = request.get_json(force=True)
    db_execute("UPDATE roles SET status=%s WHERE id=%s AND is_system=0",(d['status'],d['role_id']))
    return jsonify({'code':0})

@app.route('/admin/api/role_del', methods=['POST'])
@admin_required
def role_del():
    d = request.get_json(force=True)
    rid = d['role_id']
    db_execute("DELETE FROM role_permissions WHERE role_id=%s",(rid,))
    db_execute("DELETE FROM user_roles WHERE role_id=%s",(rid,))
    db_execute("DELETE FROM roles WHERE id=%s AND is_system=0",(rid,))
    return jsonify({'code':0})

@app.route('/admin/api/role_perm_set', methods=['POST'])
@admin_required
def role_perm_set():
    d = request.get_json(force=True)
    rid, mid, lv = d['role_id'], d['module_id'], d.get('perm_level')
    if lv:
        db_execute("INSERT INTO role_permissions (role_id,module_id,perm_level) VALUES (%s,%s,%s) ON DUPLICATE KEY UPDATE perm_level=%s",(rid,mid,lv,lv))
    else:
        db_execute("DELETE FROM role_permissions WHERE role_id=%s AND module_id=%s",(rid,mid))
    return jsonify({'code':0})

@app.route('/admin/api/role_add_user', methods=['POST'])
@admin_required
def role_add_user():
    d = request.get_json(force=True)
    db_execute("INSERT IGNORE INTO user_roles (user_id,role_id) VALUES (%s,%s)",(d['user_id'],d['role_id']))
    return jsonify({'code':0})

@app.route('/admin/api/role_remove_user', methods=['POST'])
@admin_required
def role_remove_user():
    d = request.get_json(force=True)
    db_execute("DELETE FROM user_roles WHERE user_id=%s AND role_id=%s",(d['user_id'],d['role_id']))
    return jsonify({'code':0})

@app.route('/admin/api/user_role_set', methods=['POST'])
@admin_required
def user_role_set():
    d = request.get_json(force=True)
    uid, rid, v = d['user_id'], d['role_id'], d['value']
    if v:
        db_execute("INSERT IGNORE INTO user_roles (user_id,role_id) VALUES (%s,%s)",(uid,rid))
    else:
        db_execute("DELETE FROM user_roles WHERE user_id=%s AND role_id=%s",(uid,rid))
    return jsonify({'code':0})

@app.route('/admin/api/account_add', methods=['POST'])
@admin_required
def account_add():
    d = request.get_json(force=True)
    db_execute("INSERT INTO tq_accounts (account_name,tq_username,tq_password) VALUES (%s,%s,%s)",(d['name'],d['user'],encrypt_secret(d['pass'])))
    return jsonify({'code':0})

@app.route('/admin/api/account_toggle', methods=['POST'])
@admin_required
def account_toggle():
    d = request.get_json(force=True)
    db_execute("UPDATE tq_accounts SET status=%s WHERE id=%s",(d['status'],d['id']))
    return jsonify({'code':0})

@app.route('/admin/api/account_assign', methods=['POST'])
@admin_required
def account_assign():
    d = request.get_json(force=True)
    uid, aid, v = d['user_id'], d['account_id'], d['value']
    if v:
        db_execute("INSERT IGNORE INTO user_accounts (user_id,account_id) VALUES (%s,%s)",(uid,aid))
    else:
        db_execute("DELETE FROM user_accounts WHERE user_id=%s AND account_id=%s",(uid,aid))
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

# ========== 启动 ==========
def main():
    print("="*60)
    print("  stock_main v4.0 - RBAC权限体系")
    print("  角色管理 | 模块权限 | 数据隔离(账户级)")
    print(f"  端口: {CENTER_PORT}")
    print("="*60)
    init_db()
    migrate_tq_passwords()
    threading.Thread(target=heartbeat_checker, daemon=True).start()
    print(f"[心跳] 已启动 (间隔{HEARTBEAT_INTERVAL}s)")
    app.run(host='0.0.0.0', port=CENTER_PORT, debug=False, use_reloader=False)

if __name__ == '__main__':
    main()