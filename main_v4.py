"""
stock_main v4.0 - RBAC权限体系 + 模块权限 + 数据隔离
功能: 用户登录/注册 | 角色管理 | 模块权限(角色+个人) | 天勤账户分配 | 服务注册 | 心跳检测 | API网关
端口: 9000
"""
import threading, time, uuid, hashlib, secrets, requests, base64, os, hmac, json
from cryptography.fernet import Fernet
from datetime import datetime, timezone, timedelta
import configparser
from flask import Flask, request, jsonify, Response, session, redirect, url_for
import pymysql

# ========== 配置 ==========
# 库配置来源优先级: 1) 环境变量 APP_CONFIG 指向的 config.ini(安装版 launcher 会设);
#                      2) 脚本同目录 config.ini;  3) 内置默认值(dev 环境走这条)。
# dev 与打包版共用同一实现 —— 两版只靠 config.ini 的有无来区分环境, 源码不再分叉。
_CONFIG_FILE = None          # 实际生效的配置文件路径(None = 未找到, 全用默认值)


def _load_db_config(defaults):
    global _CONFIG_FILE
    cfg_path = os.environ.get("APP_CONFIG")
    if not (cfg_path and os.path.isfile(cfg_path)):
        here = os.path.dirname(os.path.abspath(__file__))
        cand = os.path.join(here, "config.ini")
        if os.path.isfile(cand):
            cfg_path = cand
    if cfg_path and os.path.isfile(cfg_path):
        try:
            cp = configparser.ConfigParser()
            cp.read(cfg_path, encoding="utf-8")
            if cp.has_section("database"):
                d = dict(defaults)
                for k in ("host", "port", "user", "password", "database", "charset"):
                    if cp.has_option("database", k):
                        v = cp.get("database", k).strip()
                        if k == "port":
                            try:
                                v = int(v)
                            except Exception:
                                pass
                        d[k] = v
                _CONFIG_FILE = cfg_path
                return d
        except Exception:
            pass
    return dict(defaults)


DB_CONFIG = _load_db_config({
    'host': '192.168.0.106', 'port': 3304,
    'user': 'zhq', 'password': 'zhq1',
    'database': 'd_lnx_tqhq',
    'charset': 'utf8mb4'
})


def _cfg_get(section, key, default=''):
    """读 config.ini 的 [section] key; 没配置文件/没该键时返回 default。"""
    if not _CONFIG_FILE:
        return default
    try:
        cp = configparser.ConfigParser()
        cp.read(_CONFIG_FILE, encoding='utf-8')
        if cp.has_section(section) and cp.has_option(section, key):
            return cp.get(section, key).strip()
    except Exception:
        pass
    return default


# ========== 数据库配置下发(子服务注册时取用) ==========
# 网关是数据库配置的唯一来源: 子服务注册时由网关下发, 子服务不再各配一份 config.ini。
# 安全: 默认只对"本机(回环)"子服务下发库凭据; 跨机多开发者场景需在 config.ini 显式开启
#       [center] db_dispatch_remote = 1。
DB_DISPATCH_REMOTE = str(_cfg_get('center', 'db_dispatch_remote', '0')).strip().lower() \
    in ('1', 'true', 'yes', 'on')

_LOOPBACK = ('127.0.0.1', '::1', 'localhost', '::ffff:127.0.0.1', '')


def public_db_config():
    """下发给子服务的库连接信息(不含 mode 之类的本地策略)。"""
    return {
        'host': DB_CONFIG.get('host'),
        'port': DB_CONFIG.get('port'),
        'user': DB_CONFIG.get('user'),
        'password': DB_CONFIG.get('password'),
        'database': DB_CONFIG.get('database'),
        'charset': DB_CONFIG.get('charset', 'utf8mb4'),
    }


def db_source_desc():
    return ('config.ini(%s)' % _CONFIG_FILE) if _CONFIG_FILE else '网关内置默认值'


GW_DB_CONFIG_HEADER = 'X-Gw-Db-Config'   # 路由转发时携带库配置的请求头名


def db_dispatch_allowed(target_ip=None):
    """是否允许向目标子服务下发库凭据。返回 (bool, 拒绝原因)。

    target_ip: 目标子服务的 host(从 service_registry 取出); 缺省取本次请求来源 remote_addr。
    判定优先级:
      1) 显式开启 [center] db_dispatch_remote = 1 -> 放行所有(含任意外网, 仅信任局域网时用)。
      2) 目标为本机回环 -> 放行(默认仅这一档)。
      3) 目标是【已注册且 ONLINE】的子服务(多开发者局域网共用网关) -> 放行,
         这样其他开发者的子服务也能拿到库配置, 又不会把库口令暴露给任意外网。
    """
    ip = (target_ip or (request.remote_addr or '')).strip()
    if DB_DISPATCH_REMOTE:
        return True, ''
    if ip in _LOOPBACK:
        return True, ''
    # 白名单: 已注册并 ONLINE 的子服务 host —— 局域网多开发者场景安全放行
    try:
        row = db_one("SELECT 1 FROM service_registry WHERE host=%s AND status='ONLINE'", (ip,))
        if row:
            return True, ''
    except Exception:
        pass
    return False, ('目标 %s 非本机且未开 db_dispatch_remote, 默认不下发库凭据; '
                   '如需跨机下发请在网关 config.ini 加 [center] db_dispatch_remote = 1' % ip)

# ========== 子服务注册码 (准入控制, 2026-09-22) ==========
# 背景: /register 原先没有任何鉴权 —— 任何能访问网关的人 POST 三个字段就能把自己挂上
#       /api/gw/<key>/ 路由; 更直接的还有直写 service_registry 表(对方自研 client 就这么干)。
# 现在: 子服务注册时必须携带注册码(register_code), 不带或带错一律 403 拒绝。
# 定位: 准入凭据, 不是加密手段 —— 网关跑的是明文 HTTP, 链路上能看到的一样能看到。
# 来源优先级: 环境变量 STOCK_REGISTER_CODE > config.ini [center] register_code > 内置默认值。
# 特例: 显式配置成空串 = 关闭校验(应急逃生口; 会让注册口重新变成公开的, 慎用)。
DEFAULT_REGISTER_CODE = 'stock-gw-2026-0922'


def _resolve_secret_key():
    """返回 (secret_key, 来源描述)。

    [2026-10-09 修复] 原为 SECRET_KEY = secrets.token_hex(32) —— 网关每重启一次就换密钥,
    Flask session cookie 签名校验随之全盘失效, 所有在线浏览器被 login_required 302 踢回
    /login(表现为"页面加载不出来/列表卡加载中")。改为优先级:
      1) 环境变量 STOCK_SECRET_KEY(部署/容器场景显式注入)
      2) 密钥文件(优先 %PROGRAMDATA%, 回落脚本同目录 .secret_key —— 仅当前用户可读写)
      3) 都不存在 -> 首次生成并写入密钥文件
    密钥文件保证跨重启稳定, 同时避免明文写进 config.ini。
    """
    _env = (os.environ.get('STOCK_SECRET_KEY') or '').strip()
    if _env:
        return _env, '环境变量 STOCK_SECRET_KEY'
    # 密钥文件候选路径: PROGRAMDATA(安装版, 天然按用户隔离) -> 脚本同目录(dev)
    _cands = []
    _pd = os.environ.get('PROGRAMDATA')
    if _pd:
        _cands.append(os.path.join(_pd, 'StockGW', 'secret.key'))
    _cands.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.secret_key'))
    for _p in _cands:
        try:
            if os.path.isfile(_p):
                with open(_p, 'r', encoding='utf-8') as _f:
                    _v = _f.read().strip()
                if _v:
                    return _v, '密钥文件 ' + _p
        except Exception:
            pass
    # 首次生成 -> 落盘(目录不存在则建), 权限尽量收紧到仅当前用户可读写
    _k = secrets.token_hex(32)
    for _p in _cands:
        try:
            _d = os.path.dirname(_p)
            if _d and not os.path.isdir(_d):
                os.makedirs(_d, exist_ok=True)
            with open(_p, 'w', encoding='utf-8') as _f:
                _f.write(_k)
            try:
                os.chmod(_p, 0o600)      # POSIX(安装包在 Windows 下为 no-op, 由目录 ACL 保证)
            except Exception:
                pass
            return _k, '新生成并写入 ' + _p
        except Exception:
            continue
    return _k, '新生成(未能落盘, 重启后 session 会失效)'


def _resolve_register_code():
    """返回 (注册码, 来源描述)。注册码为空串表示关闭校验。"""
    _env = (os.environ.get('STOCK_REGISTER_CODE') or '').strip()
    if _env:
        return _env, '环境变量 STOCK_REGISTER_CODE'
    if _CONFIG_FILE:
        try:
            _cp = configparser.ConfigParser()
            _cp.read(_CONFIG_FILE, encoding='utf-8')
            if _cp.has_section('center') and _cp.has_option('center', 'register_code'):
                return _cp.get('center', 'register_code').strip(), 'config.ini [center] register_code'
        except Exception:
            pass
    return DEFAULT_REGISTER_CODE, '网关内置默认值'


REGISTER_CODE, REGISTER_CODE_SRC = _resolve_register_code()

CENTER_PORT = 9000
HEARTBEAT_INTERVAL = 10
HEARTBEAT_TIMEOUT = 30
MAX_HEARTBEAT_FAILS = 3
SECRET_KEY, SECRET_KEY_SRC = _resolve_secret_key()

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

# ========== 数据库连接(限时等待重试) ==========
# 安装版依赖随包便携 MySQL(默认 127.0.0.1:3399)。其首启/老机器可能要几十秒才可连;
# 旧实现这里是"一次连接, 失败即抛未捕获异常" → 进程直接退出(PYI-41620), 用户只看到
# WinError 10061 + 英文栈, 完全不知道该怎么办。现改为: 限时等待重试 → 仍失败则打印
# 可执行的中文指引后干净退出(exit 1), 不再裸抛 traceback。
try:
    DB_CONNECT_WAIT = int(os.environ.get('STOCK_DB_WAIT', '120'))
except Exception:
    DB_CONNECT_WAIT = 120
DB_CONNECT_INTERVAL = 2.0


def _db_hint():
    """连库失败时的可执行指引(按最可能的原因排序)。"""
    h = DB_CONFIG.get('host')
    p = DB_CONFIG.get('port')
    d = DB_CONFIG.get('database')
    return (
        f"[库] 无法连接数据库 {h}:{p} (库名 {d})。\n"
        "[库] 常见原因与处理:\n"
        "[库]   1) 必须通过 launcher.exe(桌面快捷方式)启动 —— 它会先拉起随包数据库;\n"
        "[库]      直接双击 stock_main.exe 不会启动数据库, 必然连不上;\n"
        "[库]   2) 数据库还在启动中/启动失败: 看安装目录下 logs/mysqld.log 的最后几行;\n"
        "[库]   3) 端口被占用或被安全软件拦截: cmd 执行 netstat -ano | findstr 3399;\n"
        "[库]   4) 若用的是外部数据库, 检查 config.ini [database] 的 host/port/账号口令。"
    )


def connect_db(timeout=None):
    """限时重试连接数据库; 超时则打印中文指引并 exit(1)。"""
    import sys as _sys
    left = DB_CONNECT_WAIT if timeout is None else int(timeout)
    deadline = time.time() + max(0, left)
    err = None
    first = True
    while True:
        try:
            return pymysql.connect(**DB_CONFIG)
        except Exception as e:
            err = e
            if time.time() >= deadline:
                break
            if first:
                print("[库] 数据库暂不可用(端口可能还没起来), 等待就绪… "
                      f"{DB_CONFIG.get('host')}:{DB_CONFIG.get('port')}", flush=True)
                first = False
            time.sleep(DB_CONNECT_INTERVAL)
    print(f"[库] 等待 {left}s 后仍无法连接: {err}", flush=True)
    print(_db_hint(), flush=True)
    _sys.exit(1)


def init_db():
    conn = connect_db(); cur = conn.cursor()

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
        expiry DATETIME NULL COMMENT '天勤授权到期时间(免费=2099-12-31)',
        product_type VARCHAR(50) DEFAULT '' COMMENT '天勤版本类型(trial/专业版/企业版)',
        expire_checked_at DATETIME NULL COMMENT '最后检查到期时间',
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

    # ===== 期货K线模块(futureskline): 独立"期货监控"模块, K线图 + 周期切换 =====
    # [2026-10-09 用户裁定] 导航栏显示名"期货K线" -> "期货监控"(该模块默认落地全市场信号
    # 监控整页, 原名已不符实义)。只改 module_name, module_key/route_path/icon 一律不动,
    # 故 RBAC 权限与路由完全兼容(沿用 expiry->期货到期表 的幂等改名范式)。
    if not db_one("SELECT 1 FROM modules WHERE module_key='futureskline'"):
        cur.execute("INSERT INTO modules (module_name,module_key,service_name,route_path,icon,sort_order,status) VALUES ('期货监控','futureskline','stock-app-01','/futureskline','🕯️',9,1)")
    _fk_name = db_one("SELECT module_name FROM modules WHERE module_key='futureskline'")
    if _fk_name and _fk_name[0] != '期货监控':
        cur.execute("UPDATE modules SET module_name='期货监控' WHERE module_key='futureskline'")
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

    # ===== 多周期技术分析模块(stocktech): 1分~日线 六周期指标矩阵 =====
    if not db_one("SELECT 1 FROM modules WHERE module_key='stocktech'"):
        cur.execute("INSERT INTO modules (module_name,module_key,service_name,route_path,icon,sort_order,status) VALUES ('技术分析','stocktech','stock-app-01','/stocktech','📊',12,1)")
    _st_id = db_one("SELECT id FROM modules WHERE module_key='stocktech'")
    if _st_id:
        for _rid, _lvl in [(1, 'admin'), (2, 'use'), (3, 'view')]:
            if not db_one("SELECT 1 FROM role_permissions WHERE role_id=%s AND module_id=%s", (_rid, _st_id[0])):
                cur.execute("INSERT INTO role_permissions (role_id,module_id,perm_level) VALUES (%s,%s,%s)", (_rid, _st_id[0], _lvl))

    # ===== 期权费率模块(optrate): 独立大模块 =====
    # 费率 = 平值期权价 / 标的价格 × 365 / 到期天数; 分低(<5%)/高(>500%)两分区各自排序。
    # 与 股票(stockkline) / 技术分析(stocktech) / 期权(optchain) 并列, 左侧菜单独立一项。
    if not db_one("SELECT 1 FROM modules WHERE module_key='optrate'"):
        cur.execute("INSERT INTO modules (module_name,module_key,service_name,route_path,icon,sort_order,status) VALUES ('期权费率','optrate','stock-app-01','/optrate','📐',13,1)")
    _or_id = db_one("SELECT id FROM modules WHERE module_key='optrate'")
    if _or_id:
        for _rid, _lvl in [(1, 'admin'), (2, 'use'), (3, 'view')]:
            if not db_one("SELECT 1 FROM role_permissions WHERE role_id=%s AND module_id=%s", (_rid, _or_id[0])):
                cur.execute("INSERT INTO role_permissions (role_id,module_id,perm_level) VALUES (%s,%s,%s)", (_rid, _or_id[0], _lvl))

    # ===== 登录提示中心 (v4.1): 公告表 + 已读回执表 =====
    # level: important=每次登录都弹(直到事项解决/管理员下架)  normal=用户关闭一次后永久不再弹
    cur.execute('''CREATE TABLE IF NOT EXISTS t_login_notice (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(200) NOT NULL COMMENT '标题',
        content TEXT COMMENT '正文(支持换行)',
        level VARCHAR(20) DEFAULT 'normal' COMMENT 'important=重要(每次登录弹) normal=普通(关闭一次不再弹)',
        enabled TINYINT DEFAULT 1 COMMENT '1=生效 0=下架',
        target_type VARCHAR(20) DEFAULT 'all' COMMENT 'all=全部用户 role=按角色 user=指定用户',
        target_value VARCHAR(300) DEFAULT '' COMMENT '角色key或用户名, 多个逗号分隔',
        start_at DATETIME NULL COMMENT '生效开始(空=立即)',
        end_at DATETIME NULL COMMENT '生效结束(空=长期)',
        hit_count INT DEFAULT 0 COMMENT '累计展示次数',
        create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        KEY idx_enabled (enabled, level)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')

    cur.execute('''CREATE TABLE IF NOT EXISTS t_login_notice_ack (
        id INT AUTO_INCREMENT PRIMARY KEY,
        notice_id INT NULL COMMENT '公告id(系统自动类型为NULL)',
        notice_key VARCHAR(64) NOT NULL DEFAULT '' COMMENT '提示唯一键: db_<id> / sys_xxx',
        user_id INT NOT NULL,
        ack_time DATETIME NULL,
        UNIQUE KEY uk_nk (notice_key, user_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')
    # 兼容早期回执表(只有 notice_id 且 NOT NULL, 无 notice_key)
    _ack_cols = {r[0] for r in db_execute(
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='t_login_notice_ack'")}
    if 'notice_key' not in _ack_cols:
        cur.execute("ALTER TABLE t_login_notice_ack ADD COLUMN notice_key VARCHAR(64) NOT NULL DEFAULT ''")
    try:
        cur.execute("ALTER TABLE t_login_notice_ack MODIFY notice_id INT NULL")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE t_login_notice_ack ADD UNIQUE KEY uk_nk (notice_key, user_id)")
    except Exception:
        pass

    # 全局设置项(登录提示相关阈值等), 键值表
    cur.execute('''CREATE TABLE IF NOT EXISTS t_gw_setting (
        k VARCHAR(64) PRIMARY KEY,
        v VARCHAR(300) DEFAULT '',
        memo VARCHAR(200) DEFAULT ''
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')
    if not db_one("SELECT 1 FROM t_gw_setting WHERE k='acct_expire_warn_days'"):
        cur.execute("INSERT INTO t_gw_setting (k,v,memo) VALUES ('acct_expire_warn_days','3','账户到期前N天开始登录提醒')")

    conn.commit(); conn.close()
    print("[DB] 所有表就绪 (12张: 注册+用户+账户+模块+用户账户+用户权限+角色+角色权限+用户角色+登录提示+提示回执+全局设置)")

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


def migrate_tq_accounts_expiry():
    """为已存在的 tq_accounts 表补齐到期时间相关列(幂等, 兼容 MySQL 5.7 无 ADD COLUMN IF NOT EXISTS)。"""
    cols = {r[0] for r in db_execute(
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tq_accounts'")}
    _add = []
    if 'expiry' not in cols:
        _add.append("ADD COLUMN expiry DATETIME NULL COMMENT '天勤授权到期时间(免费=2099-12-31)'")
    if 'product_type' not in cols:
        _add.append("ADD COLUMN product_type VARCHAR(50) DEFAULT '' COMMENT '天勤版本类型'")
    if 'expire_checked_at' not in cols:
        _add.append("ADD COLUMN expire_checked_at DATETIME NULL COMMENT '最后检查到期时间'")
    if _add:
        db_execute("ALTER TABLE tq_accounts " + ", ".join(_add))
        print(f"[迁移] tq_accounts 补齐到期列: {len(_add)} 列")


# ========== 账户到期时间刷新 (定时从天勤 auth 接口拉取) ==========
ACCOUNT_EXPIRY_INTERVAL = 300   # 每 5 分钟刷新一次账户到期状态
_TQ_AUTH_URL = "https://auth.shinnytech.com"


def _tq_auth_expiry(username, password):
    """调用天勤 auth 接口获取账户授权信息(纯 HTTP, 不依赖 tqsdk, 不占用行情连接)。

    返回 (expire_datetime, product_type, days_left) —— expire_datetime 为东八区 datetime,
    免费账户为 2099-12-31 23:59:59(永不过期)。失败抛异常, 由调用方保留旧值并记录。"""
    r = requests.post(
        f"{_TQ_AUTH_URL}/auth/realms/shinnytech/protocol/openid-connect/token",
        data={
            "client_id": "shinny_tq",
            "client_secret": "be30b9f4-6862-488a-99ad-21bde0400081",
            "grant_type": "password",
            "username": username,
            "password": password,
        },
        timeout=30,
    )
    if r.status_code != 200:
        raise Exception(f"天勤认证失败({r.status_code})")
    token = r.json().get("access_token", "")
    if not token:
        raise Exception("天勤认证失败(无 token)")
    r2 = requests.get(
        f"{_TQ_AUTH_URL}/auth/realms/shinnytech/rest/get-grant/tq",
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )
    if r2.status_code != 200:
        raise Exception(f"查询授权失败({r2.status_code})")
    c = r2.json()
    exp = datetime.fromtimestamp(c.get("exp", 0), tz=timezone(timedelta(hours=8)))
    return exp, c.get("account_type", ""), c.get("daysleft")


def is_account_expired(expiry):
    """判断账户是否过期。expiry 为 None 表示尚未探测(视为有效, 不误伤), 否则与当前时间比较。"""
    if expiry is None:
        return False
    now = datetime.now()
    if expiry.tzinfo is not None:
        now = now.astimezone(expiry.tzinfo)
    return expiry < now


def account_expiry_checker():
    """后台线程: 定时遍历所有天勤账户, 拉取授权到期时间写入表, 更新过期状态。

    到期时间写入 tq_accounts.expiry / product_type / expire_checked_at;
    过期账户不再置 status=0: status 为管理员启用开关(独立), 过期仅更新 expiry 标记, 免费行情仍可取,
    付费标的由下游白名单按 product_type 拦截。"""
    while True:
        try:
            rows = db_execute("SELECT id,tq_username,tq_password FROM tq_accounts")
            for aid, username, cipher in rows:
                try:
                    pwd = decrypt_secret(cipher)
                    exp, ptype, days = _tq_auth_expiry(username, pwd)
                    expired = is_account_expired(exp)
                    db_execute(
                        "UPDATE tq_accounts SET expiry=%s, product_type=%s, expire_checked_at=NOW() WHERE id=%s",
                        (exp.strftime("%Y-%m-%d %H:%M:%S") if exp else None,
                         ptype, aid))
                    print(f"[账户到期] {username} {ptype} 到期={exp} 剩余={days}天 {'已过期' if expired else '有效'}", flush=True)
                except Exception as e:
                    # 网络/认证失败: 保留旧 expiry, 仅记录检查时间
                    db_execute("UPDATE tq_accounts SET expire_checked_at=NOW() WHERE id=%s", (aid,))
                    print(f"[账户到期] {username} 检查失败: {str(e)[:80]}", flush=True)
        except Exception as e:
            print(f"[账户到期] 刷新任务异常: {e}", flush=True)
        time.sleep(ACCOUNT_EXPIRY_INTERVAL)

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
    """返回用户绑定的【已启用】账户(status=1)。过期账户不再被整条判死——仍返回但排末尾,
    由前端提示"试用到期, 免费行情仍可用"。免费期货/期权/指数行情不受 expiry 影响。

    账户是否过期由后台 account_expiry_checker 定时从天勤拉取并写入 expiry 后判定。
    付费标的(A股/ETF/期权Greeks等)由下游白名单按账户 product_type 拦截, 而非在此掐断。"""
    rows = db_execute(
        "SELECT a.id,a.account_name,a.tq_username,a.expiry,a.product_type FROM tq_accounts a "
        "JOIN user_accounts ua ON a.id=ua.account_id "
        "WHERE ua.user_id=%s AND a.status=1 ORDER BY (a.expiry IS NULL OR a.expiry > NOW()) DESC, a.id", (user_id,))
    return [{'id': r[0], 'name': r[1], 'username': r[2],
             'expiry': (r[3].strftime('%Y-%m-%d %H:%M:%S') if r[3] else None),
             'product_type': r[4]} for r in rows]


def is_account_valid(account_id):
    """校验指定账户当前是否有效(启用且未过期)。用于网关代理注入前校验。"""
    row = db_one(
        "SELECT 1 FROM tq_accounts WHERE id=%s AND status=1",
        (account_id,))
    return row is not None


# ========== 登录提示中心 (v4.1) ==========
# 两类提示(用户裁定按重要性分档):
#   important 重要 —— 每次登录都弹, 直到事项本身解决或管理员下架该公告;
#                    用户点×只关掉本次, 不影响下次登录。
#   normal    普通 —— 用户关闭一次即永久不再看到(按 key 写回执表)。
# 来源两类:
#   自动类型  系统按实际情况生成内容, 不需要人工维护, 也不进公告表。
#             目前一种: 账户即将到期(剩余 ≤ 阈值天且尚未过期 → 登录提醒一次;
#             已经过期的不再提醒)。
#   人工公告  t_login_notice 里 enabled=1 且在生效时间窗内、命中投放对象的行。
NOTICE_LEVEL_META = {
    'important': {'label': '重要', 'color': '#ff8a8a', 'bg': 'rgba(255,138,138,.15)', 'icon': '⚠️'},
    'normal':    {'label': '通知', 'color': '#7dd3fc', 'bg': 'rgba(56,189,248,.15)',  'icon': '🔔'},
}


def get_setting(k, default=''):
    row = db_one("SELECT v FROM t_gw_setting WHERE k=%s", (k,))
    return row[0] if row else default


def set_setting(k, v, memo=''):
    if db_one("SELECT 1 FROM t_gw_setting WHERE k=%s", (k,)):
        db_execute("UPDATE t_gw_setting SET v=%s WHERE k=%s", (str(v), k))
    else:
        db_execute("INSERT INTO t_gw_setting (k,v,memo) VALUES (%s,%s,%s)", (k, str(v), memo))


def get_acct_expire_warn_days():
    """账户到期前多少天开始提醒(默认3天, 后台可改)。"""
    try:
        return max(0, int(get_setting('acct_expire_warn_days', '3')))
    except Exception:
        return 3


def get_user_role_keys(user_id):
    """取用户拥有的角色标识集合(admin/trader/viewer...), 供公告按角色投放匹配。"""
    rows = db_execute(
        "SELECT r.role_key FROM user_roles ur JOIN roles r ON ur.role_id=r.id "
        "WHERE ur.user_id=%s AND r.status=1", (user_id,))
    keys = {r[0] for r in rows}
    if db_one("SELECT 1 FROM users WHERE id=%s AND is_admin=1", (user_id,)):
        keys.add('admin')
    return keys


def _notice_target_match(target_type, target_value, user_id, username, role_keys, is_admin):
    tt = (target_type or 'all').strip()
    if tt == 'all':
        return True
    vals = [v.strip() for v in (target_value or '').split(',') if v.strip()]
    if not vals:
        return False
    if tt == 'role':
        return any(v in role_keys for v in vals)
    if tt == 'user':
        return username in vals
    return False


def _notice_acked(user_id, key):
    """该用户是否已关闭过这条提示(按 key 记回执)。"""
    return db_one("SELECT 1 FROM t_login_notice_ack WHERE notice_key=%s AND user_id=%s",
                  (key, user_id)) is not None


def build_login_notices(user_id, username, is_admin):
    """组装该用户本次登录需要弹出的提示列表。

    自动类型(系统按实际情况生成内容, 无需人工维护): 账户即将到期 ——
    剩余天数 ≤ 阈值(默认3天, 后台可改, 0=关闭) 且 **尚未过期** 时提醒;
    属 important 级 => **每次登录都弹**, 关掉只关当次; 已过期的账户不再提醒
    (过期账户不再被 account_expiry_checker 置 status=0, 仍可被查到; 仅 expiry 标记过期, 免费行情仍可取)。
    自然终止: 续费后不再临近到期 => 该提示自动消失。

    返回 list[dict]: {key, level, title, content, source, notice_id}
    level=normal 且已有回执的会被过滤(关闭过一次不再提醒)。"""
    out = []
    # ---- 1) 自动类型: 账户即将到期(只提醒"快到期但还没到期"的) ----
    warn_days = get_acct_expire_warn_days()
    if warn_days > 0:
        now = datetime.now()
        rows = db_execute(
            "SELECT a.id, a.account_name, a.tq_username, a.expiry FROM tq_accounts a "
            "JOIN user_accounts ua ON a.id=ua.account_id "
            "WHERE ua.user_id=%s AND a.status=1 AND a.expiry IS NOT NULL "
            "AND a.expiry > NOW() AND a.expiry <= DATE_ADD(NOW(), INTERVAL %s DAY) "
            "ORDER BY a.expiry", (user_id, warn_days))
        for aid, aname, auname, expiry in rows:
            left = max((expiry - now).days, 0)
            # key 带账户id+到期日: 续费后再临近到期会重新提醒一次
            key = f'sys_exp_{aid}_{expiry.strftime("%Y%m%d")}'
            # 用户裁定(2026-09-12): 快到期 => 每次登录都弹(important), 不落回执;
            # 续费后不再临近到期(或账户被停用)即自然消失, 无需人工关闭。
            out.append({
                'key': key, 'level': 'important', 'source': 'system', 'notice_id': None,
                'title': f'{aname or auname} 即将到期',
                'content': f'天勤账户 {auname} 将于 {expiry.strftime("%Y-%m-%d %H:%M")} 到期，'
                           f'剩余 {left} 天。\n到期后该账户的行情、K线、期权数据将不可用，请及时续费。',
            })

    # ---- 2) 人工公告 ----
    role_keys = get_user_role_keys(user_id)
    rows = db_execute(
        "SELECT id,title,content,level,target_type,target_value FROM t_login_notice "
        "WHERE enabled=1 AND (start_at IS NULL OR start_at<=NOW()) AND (end_at IS NULL OR end_at>=NOW()) "
        "ORDER BY (level='important') DESC, id DESC")
    for nid, title, content, level, ttype, tval in rows:
        level = level if level in NOTICE_LEVEL_META else 'normal'
        if not _notice_target_match(ttype, tval, user_id, username, role_keys, is_admin):
            continue
        key = f'db_{nid}'
        if level == 'normal' and _notice_acked(user_id, key):
            continue
        out.append({
            'key': key, 'level': level, 'source': 'db',
            'notice_id': nid, 'title': title, 'content': content or '',
        })
    return out


def get_login_notices_cached():
    """取本次登录会话应展示的提示。

    规则:
      · 用户关闭弹窗后 session['notice_shown']=True -> 本次会话内刷新 /app 不再重复弹;
      · 但若此后**出现了本会话没展示过的提示**(管理员新发布公告/新账户临近到期),
        则重新弹出 —— 用 session['notice_seen_keys'] 记录已展示过的 key 来判断,
        因此不存在"旧空列表把新公告挡住"的问题;
      · 重新登录时 api_login 会清掉上述会话标记 -> "重要"提示每次登录都会再弹。

    这里**不缓存列表**, 每次渲染实时计算(2~3 条轻量查询, /app 不是轮询端点)。
    """
    lst = build_login_notices(session['user_id'], session.get('username', ''),
                              bool(session.get('is_admin')))
    if not lst:
        return []
    seen = set(session.get('notice_seen_keys') or [])
    if session.get('notice_shown'):
        # 本次会话已关过弹窗 -> 只弹"此后新出现、还没展示过"的提示
        lst = [n for n in lst if n['key'] not in seen]
        if not lst:
            return []
    session['notice_seen_keys'] = list(seen | {n['key'] for n in lst})
    if not session.get('notice_hit_counted'):
        session['notice_hit_counted'] = True  # 展示次数每次登录只计一次
        for nid in [n['notice_id'] for n in lst if n['notice_id']]:
            try:
                db_execute("UPDATE t_login_notice SET hit_count=hit_count+1 WHERE id=%s", (nid,))
            except Exception:
                pass
    return lst


# ========== 心跳检测 ==========
def heartbeat_checker():
    while True:
        try:
            # 检测所有已注册服务，OFFLINE 服务恢复后也能自动恢复 ONLINE
            rows = db_execute("SELECT service_name,host,port,service_token,heartbeat_fail_count,status FROM service_registry")
            for name, host, port, token, fail_count, status in rows:
                try:
                    resp = requests.get(f"http://{host}:{port}/health", params={'token':token}, timeout=5)
                    # 判活兼容：标准约定 {"alive":true}；同时兼容只回 {"status":"ok"} 的服务，
                    # 避免因缺 alive 字段被每轮判失败 → 30s 后误置 OFFLINE（服务"连上又断"）。
                    try: _hj = resp.json() or {}
                    except Exception: _hj = {}
                    _alive = bool(_hj.get('alive')) or str(_hj.get('status','')).lower() in ('ok','alive','up','healthy')
                    if resp.status_code==200 and _alive:
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
    # 注册码准入校验: 网关配了注册码就必须带对(常量时间比较, 避免时序侧信道)
    if REGISTER_CODE:
        _rc = str(data.get('register_code') or '').strip()
        if not _rc or not hmac.compare_digest(_rc.encode('utf-8'), REGISTER_CODE.encode('utf-8')):
            _why = '未携带注册码' if not _rc else '注册码不正确'
            print(f"[注册] 拒绝 {sn}@{request.remote_addr}: {_why}", flush=True)
            return jsonify({'code':-1, 'msg':_why, 'need_register_code':True,
                            'hint':('请向网关管理员索取注册码, 并在子服务设置环境变量 '
                                    'STOCK_REGISTER_CODE(或 config.ini [center] register_code)')}), 403
    routes = data.get('routes','')
    token = str(uuid.uuid4())
    gw_secret = secrets.token_hex(32)
    try:
        if db_one("SELECT 1 FROM service_registry WHERE service_name=%s",(sn,)):
            db_execute("UPDATE service_registry SET host=%s,port=%s,service_token=%s,routes=%s,gw_secret=%s,status='ONLINE',last_heartbeat=%s,heartbeat_fail_count=0 WHERE service_name=%s",(h,p,token,routes,gw_secret,datetime.now(),sn))
        else:
            db_execute("INSERT INTO service_registry (service_name,host,port,service_token,routes,gw_secret) VALUES (%s,%s,%s,%s,%s,%s)",(sn,h,p,token,routes,gw_secret))
    except Exception as e: return jsonify({'code':-1,'msg':str(e)}),500
    resp = {'code':0,'service_token':token,'gw_secret':gw_secret,'heartbeat_interval':HEARTBEAT_INTERVAL}
    # 数据库配置随注册一并下发; 不允许时明确给出原因, 子服务据此回退本地配置
    _ok, _why = db_dispatch_allowed()
    if _ok:
        resp['db'] = public_db_config()
        resp['db_source'] = db_source_desc()
    else:
        resp['db'] = None
        resp['db_reason'] = _why
        print(f"[注册] {sn} 未下发库配置: {_why}", flush=True)
    return jsonify(resp)


@app.route('/dbconfig')
def api_dbconfig():
    """子服务按需刷新数据库配置(中心切库后无需重启子服务)。
    用注册时拿到的 service_token 鉴权 —— 只有真正注册过的服务才能取。"""
    tok = (request.args.get('service_token') or '').strip()
    if not tok:
        return jsonify({'code':-1,'msg':'missing service_token'}), 400
    try:
        row = db_one("SELECT service_name FROM service_registry WHERE service_token=%s", (tok,))
    except Exception as e:
        return jsonify({'code':-1,'msg':str(e)}), 500
    if not row:
        return jsonify({'code':-1,'msg':'invalid service_token'}), 403
    _ok, _why = db_dispatch_allowed()
    if not _ok:
        return jsonify({'code':-2,'msg':_why}), 403
    return jsonify({'code':0,'db':public_db_config(),'db_source':db_source_desc()})

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
    # 每次登录都重建提示列表(重要提示因此"每次登录都弹")
    # 注意: notice_shown 必须一起清! 否则用户点过一次×后, 该标志会一直留在会话里,
    #       后续即使重新登录也会被 get_login_notices_cached 短路 -> 永远不弹。
    session.pop('notice_shown', None)
    session.pop('notice_seen_keys', None)
    session.pop('notice_hit_counted', None)
    session.pop('notice_built', None); session.pop('notice_list', None)
    accts = get_user_accounts(row[0])
    if accts:
        # 登录时自动把右上角账户设为该用户第一个有效账户(自动更改只在登录时处理)
        session['current_account_id']=accts[0]['id']; session['current_account_name']=accts[0]['name']
    session.pop('acct_expired_warn', None)
    return jsonify({'code':0,'is_admin':bool(row[1]),'no_valid_account': not accts})

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
/* 形态总数徽标(2026-10-14): "技术分析"菜单项后面, 与页面内 .tabcnt 同款琥珀圆角;
   即使用户在别的模块也能看到总数(数据源=stock_app 服务端 15s 聚合, 见 stock_tech.api_pattern_total) */
.nav-pat{font-style:normal;font-weight:700;color:#fff;background:#fbbf24;border-radius:9px;padding:0 7px;font-size:12px;line-height:18px;margin-left:6px;vertical-align:1px}
.nav-pat.stale{opacity:.45}
.main{flex:1;display:flex;flex-direction:column;min-width:0}
.topbar{height:60px;background:linear-gradient(135deg,rgba(22,30,46,.95),rgba(13,21,38,.95));border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;padding:0 20px;gap:10px;backdrop-filter:blur(8px);overflow:hidden;transition:height .22s ease,padding .18s ease,opacity .16s ease,border-bottom-color .2s}
/* 顶栏收起: 高度归零, 把 60px 全部让给内容区 */
body.topbar-hidden .topbar{height:0;padding-top:0;padding-bottom:0;border-bottom-width:0;border-bottom-color:transparent;opacity:0;pointer-events:none}
/* 收起后在内容区顶部留一条 14px 的唤回条, 点一下即展开 (不遮挡, 在流内不覆盖页面) */
.topbar-restore{display:none;flex:none;height:14px;align-items:center;justify-content:center;gap:8px;cursor:pointer;user-select:none;letter-spacing:2px;font-size:10px;color:var(--muted);background:linear-gradient(180deg,rgba(56,189,248,.13),rgba(56,189,248,0));border-bottom:1px solid rgba(56,189,248,.10);transition:background .2s,color .2s}
body.topbar-hidden .topbar-restore{display:flex}
.topbar-restore:hover{background:linear-gradient(180deg,rgba(56,189,248,.30),rgba(56,189,248,.04));color:var(--accent)}
.topbar-hide-btn{display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:10px;background:#0d1626;color:var(--muted);border:1px solid var(--border);cursor:pointer;font-size:14px;transition:.2s}
.topbar-hide-btn:hover{border-color:var(--accent);color:var(--accent);background:#111c30}
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
  .topbar-restore{height:20px;font-size:11px}
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
      <button class="topbar-hide-btn" onclick="toggleTopbar()" title="收起顶栏（把高度让给页面）" aria-label="收起顶栏">▲</button>
    </div>
  </div>
  <div class="topbar-restore" id="topbarRestore" onclick="toggleTopbar()" title="展开顶栏">▼ 顶栏已收起 · 点击展开</div>
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
  fetch('/api/account/switch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({account_id:parseInt(acctId),account_name:acctName})}).then(function(r){return r.json();}).then(function(d){if(d.code==0){loadContent();prewarmFutures();}});
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
function toggleTopbar(){
  var hidden=document.body.classList.toggle('topbar-hidden');
  try{localStorage.setItem('topbarHidden', hidden?'1':'0');}catch(e){}
}
function restoreTopbar(){
  var v='0';
  try{v=localStorage.getItem('topbarHidden')||'0';}catch(e){}
  if(v==='1') document.body.classList.add('topbar-hidden');
  else document.body.classList.remove('topbar-hidden');
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
restoreTopbar();
// —— 期货行情预热(2026-09-20 需求): 门户页打开/切换账户后立即【异步】唤醒行情账户会话 ——
// 期货行情"主连列表"首次访问需等账户会话冷启动(建连 -> 主连预注册 -> 快照落地, 可达数十秒),
// 故在此预先触发一次: 不带 warm 参数 => 后端立即返回(不等待数据), 只为尽早建好会话并预注册主连。
function prewarmFutures(){
  try{
    var sel=document.getElementById('acctSelect');
    var nm=(sel&&sel.options[sel.selectedIndex]?sel.options[sel.selectedIndex].text.split(' (')[0]:'')||'';
    fetch('/api/gw/futureskline/api/quotes?tq_acct='+encodeURIComponent(nm),{cache:'no-store'}).catch(function(){});
  }catch(e){}
}
setTimeout(prewarmFutures, 300);
// —— 形态总数徽标(2026-10-14 需求): "技术分析"菜单项后面的总数, 即使在地别的模块也可见 ——
// 数据源(2026-10-17 起): stock_app 优先返回【技术分析页每拍上报的当前页口径】, 与页面顶部
//   "🔔 形态 N"严格同源(用户诉求"没同步"); 页面从未打开时回落服务端 15s 聚合的全局口径兜底。
//   这里 20s 轮询; 超过 90s 没更新(页面已关闭)则变灰提示陈旧, 数值保留页面最后所见。
function patTotalTick(){
  fetch('/api/gw/stocktech/api/pattern_total',{cache:'no-store'}).then(function(r){return r.json();}).then(function(d){
    var el=document.getElementById('navPatTotal'); if(!el) return;
    if(d&&d.ok){
      el.textContent=String(d.total);
      var stale=(d.age<0)||(d.age>90);
      el.classList.toggle('stale',stale);
      el.title='形态总数(技术分析)'+(stale?' · 数据陈旧':'')+' · 更新于 '+(d.updated_at||'--')
        +' · 覆盖 '+d.ready+'/'+d.scope+' 个标的'
        +' · 来源 '+(d.src==='page'?'技术分析页(实时)':'服务端聚合');
    }
  }).catch(function(){});
}
setTimeout(patTotalTick,1500);
setInterval(patTotalTick,20000);
setInterval(function(){
  fetch('/api/me').then(function(r){if(!r.ok){window.top.location.href='/login';return;}return r.json();}).then(function(d){if(!d||d.code!==0){window.top.location.href='/login';}}).catch(function(){window.top.location.href='/login';});
},15000);
// —— 登录提示中心: 重要提示每次登录都弹(直到事项解决/管理员下架), 普通提示关闭一次后不再弹 ——
var NOTICES = __NOTICES_JSON__;
var noticeIdx = 0;
function escN(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function renderNotice(){
  var box=document.getElementById('noticeBody'); if(!box)return;
  var n=NOTICES[noticeIdx]; if(!n)return;
  var meta = (n.level==='important')
    ? {t:'重要',c:'#ff8a8a',bg:'rgba(255,138,138,.15)',i:'⚠️',bar:'#ff8a8a'}
    : {t:'通知',c:'#7dd3fc',bg:'rgba(56,189,248,.15)',i:'🔔',bar:'#38bdf8'};
  box.innerHTML =
    '<div style="height:4px;border-radius:4px;background:'+meta.bar+';opacity:.85;margin-bottom:16px"></div>'
    + '<div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">'
    +   '<span style="font-size:26px">'+meta.i+'</span>'
    +   '<span style="padding:3px 10px;border-radius:6px;font-size:12px;font-weight:800;background:'+meta.bg+';color:'+meta.c+'">'+meta.t+'</span>'
    +   '<span style="margin-left:auto;font-size:13px;color:#94a3b8">'+(noticeIdx+1)+' / '+NOTICES.length+'</span>'
    + '</div>'
    + '<div style="font-size:19px;font-weight:800;color:#e6edf7;margin-bottom:10px;line-height:1.5">'+escN(n.title)+'</div>'
    + '<div style="font-size:15px;color:#94a3b8;line-height:1.8;white-space:pre-wrap;max-height:46vh;overflow:auto">'+escN(n.content)+'</div>';
  var prev=document.getElementById('noticePrev'), next=document.getElementById('noticeNext');
  if(prev)prev.disabled=(noticeIdx<=0);
  if(next)next.disabled=(noticeIdx>=NOTICES.length-1);
}
function noticeNav(d){if(!NOTICES.length)return;noticeIdx=Math.min(Math.max(noticeIdx+d,0),NOTICES.length-1);renderNotice();}
function closeNoticeModal(){
  var m=document.getElementById('noticeModal'); if(m)m.style.display='none';
  // 普通提示关闭后不再提醒(按 key 记回执); 重要提示后端会忽略, 下次登录仍弹
  var keys=NOTICES.filter(function(n){return n.level!=='important';}).map(function(n){return n.key;});
  fetch('/api/notice/ack',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({keys:keys})}).catch(function(){});
}
// 注意: 本 script 位于 #noticeModal 之前(DOM 尚未解析到该节点), 必须等 DOMContentLoaded
// 再取节点, 否则 getElementById 返回 null -> 弹窗永远不显示。
function initNoticeModal(){
  if(!NOTICES.length)return;
  var m=document.getElementById('noticeModal'); if(!m)return;
  m.style.display='flex'; renderNotice();
}
if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',initNoticeModal);}else{initNoticeModal();}
</script>
<div id="noticeModal" style="display:none;position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.62);align-items:center;justify-content:center;padding:20px" onclick="if(event.target===this)closeNoticeModal()">
  <div style="position:relative;width:540px;max-width:100%;background:linear-gradient(180deg,#161e2e,#1b2538);border:1px solid #27344b;border-radius:16px;padding:26px 28px 18px;box-shadow:0 18px 50px rgba(0,0,0,.55)">
    <div onclick="closeNoticeModal()" title="关闭" style="position:absolute;top:10px;right:14px;font-size:24px;line-height:1;color:#94a3b8;cursor:pointer;padding:4px 6px;border-radius:8px">×</div>
    <div id="noticeBody"></div>
    <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:20px;border-top:1px solid #27344b;padding-top:14px">
      <button id="noticePrev" onclick="noticeNav(-1)" style="padding:10px 16px;border-radius:10px;border:1px solid #27344b;background:#1b2538;color:#e6edf7;font-size:15px;font-weight:600;cursor:pointer">‹ 上一条</button>
      <button onclick="closeNoticeModal()" style="padding:10px 22px;border:none;border-radius:10px;background:linear-gradient(135deg,#38bdf8,#c084fc);color:#08111f;font-size:15px;font-weight:800;cursor:pointer">我知道了</button>
      <button id="noticeNext" onclick="noticeNav(1)" style="padding:10px 16px;border-radius:10px;border:1px solid #27344b;background:#1b2538;color:#e6edf7;font-size:15px;font-weight:600;cursor:pointer">下一条 ›</button>
    </div>
  </div>
</div>
</body></html>
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
        # 形态总数徽标(2026-10-14): 只挂在"技术分析"项后面, 20s 轮询 /api/gw/stocktech/api/pattern_total
        pat_badge = ('<b class="nav-pat" id="navPatTotal" title="形态总数(技术分析)">–</b>'
                     if m['key'] == 'stocktech' else '')
        nav_items += f'<a href="#" class="nav-item" onclick="switchModule(\'{m["key"]}\',\'{m["route"]}\')" data-key="{m["key"]}"><span>{m["icon"]}</span> {m["name"]}{pat_badge}<span style="font-size:10px;margin-left:auto;opacity:0.5">{badge}</span></a>'
    admin_link = "<a href='#' class='nav-item' data-key='admin' onclick='switchModule(\"admin\",\"/\")' style='color:#f0c000'>⚙️ 管理后台</a>" if is_admin else ''

    notices = get_login_notices_cached()
    notices_json = json.dumps(notices, ensure_ascii=False).replace('</', '<\\/')

    return (SHELL_TEMPLATE
            .replace('__USERNAME__', session.get('username',''))
            .replace('__NAV_ITEMS__', nav_items)
            .replace('__ACCT_OPTS__', acct_opts)
            .replace('__ADMIN_LINK__', admin_link)
            .replace('__CUR_ACCT__', cur_acct)
            .replace('__NOTICES_JSON__', notices_json))

@app.route('/api/me', methods=['GET'])
@api_login_required
def api_me():
    """返回当前登录用户基本信息，供前端心跳检测会话是否仍然有效。"""
    return jsonify({'code': 0, 'user_id': session.get('user_id'), 'username': session.get('username'), 'is_admin': session.get('is_admin', False)})


@app.route('/api/notice/ack', methods=['POST'])
@api_login_required
def api_notice_ack():
    """关闭提示(按 key 记回执, 下次登录不再提醒)。

    只对 normal(普通)类落回执; important(重要)类忽略, 保证每次登录都弹。"""
    d = request.get_json(silent=True) or {}
    keys = d.get('keys') or []
    if not isinstance(keys, list):
        keys = [keys]
    uid = session['user_id']
    n = 0
    for k in keys:
        k = str(k)[:64]
        if not k:
            continue
        nid = None
        if k.startswith('db_'):
            try:
                nid = int(k[3:])
            except Exception:
                continue
            lv = db_one("SELECT level FROM t_login_notice WHERE id=%s", (nid,))
            if not lv or lv[0] != 'normal':
                continue  # 公告不存在或属重要级 -> 不落回执
        if db_one("SELECT 1 FROM t_login_notice_ack WHERE notice_key=%s AND user_id=%s", (k, uid)):
            continue
        db_execute("INSERT INTO t_login_notice_ack (notice_id,notice_key,user_id,ack_time) "
                   "VALUES (%s,%s,%s,NOW())", (nid, k, uid))
        n += 1
    # 本次登录会话内不再重复弹出(刷新 /app 也不弹); 重要提示靠下一会话重建而恢复弹出
    session['notice_shown'] = True
    return jsonify({'code': 0, 'acked': n})

@app.route('/api/account/switch', methods=['POST'])
@api_login_required
def api_switch_account():
    d = request.get_json(force=True)
    aid = d['account_id']
    # 切换不做权限限制(用户手动切换任意已启用账户); 仅校验账户存在且启用。
    # 自动更改(根据有效账户自动选中)只在登录时处理(api_login), 此处纯手动。
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
    # 注入前校验账户仍有效(未过期): 过期则不注入 tq_user/tq_pass,
    # 下游拿不到账户 -> 付费功能(行情/K线/扫描)无数据, 公共功能(日历/到期表)不受影响。
    if acct_id and is_account_valid(acct_id):
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

    # 数据库配置随路由一并下发: 子服务(本机 / 已注册 ONLINE 子服务)无需各自维护一份库配置,
    # 网关这边改一次地址, 所有子服务下一次被路由的请求就自动拿到新配置(来源=route)。
    if db_dispatch_allowed(target_ip=host):
        try:
            gw_headers[GW_DB_CONFIG_HEADER] = json.dumps(public_db_config(), ensure_ascii=False)
        except Exception:
            pass

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
        # 下游错误页(Flask 默认 HTML)不原样透传：调用方(JSON XHR / 子页面)拿到 HTML
        # 只能报“HTTP xxx 非JSON”，真正的报错被整页 HTML 淹没，排查成本极高
        # (实测：下游 500 被网关注入隐藏导航 CSS 后回给前端，前端只看到一段 <style>)。
        # 统一转成 JSON 错误，并把下游错误页 <title> 当线索带回；完整栈仍在
        # 下游服务自己的日志里(logs/<服务>.log)。
        if resp.status_code >= 400 and 'html' in content_type.lower():
            _t0 = body.find(b'<title>')
            tip = ''
            if _t0 >= 0:
                _t1 = body.find(b'</title>', _t0)
                if _t1 > _t0:
                    tip = body[_t0 + 7:_t1].decode('utf-8', 'replace').strip()
            return jsonify({'code': -1,
                            'msg': '下游服务返回 HTTP %d%s（服务 %s，详情见其日志）'
                                   % (resp.status_code,
                                      ('：' + tip) if tip else '', mod[0])}), resp.status_code
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
        # 页面/静态资源浏览器缓存: 仅对 html 整页与静态资源(JS/CSS/图片/字体)加缓存头,
        # 实时数据 API(JSON)原样不动 -> 不影响既有逻辑与实时行情。
        # 下游已自带 Cache-Control 时保留(本代理默认不透传下游头, 故此处一般为空)。
        resp_obj = Response(body, status=resp.status_code, content_type=content_type)
        if "Cache-Control" not in resp_obj.headers and resp_obj.status_code < 400:
            _ct = (content_type or "").lower()
            if "text/html" in _ct:
                resp_obj.headers["Cache-Control"] = "public, max-age=300"
            elif any(t in _ct for t in ("javascript", "css", "image/", "font/")):
                resp_obj.headers["Cache-Control"] = "public, max-age=86400"
        return resp_obj
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
  <button class="tab" onclick="showTab('notices')">📢 登录提示</button>
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

// === 登录提示 ===
function saveNotice(){
  var g=function(id){var e=document.getElementById(id);return e?e.value:''};
  api('/admin/api/notice_save',{
    id:g('ntId'),title:g('ntTitle'),content:g('ntContent'),level:g('ntLevel'),
    target_type:g('ntTargetType'),target_value:g('ntTargetValue'),
    start_at:g('ntStart'),end_at:g('ntEnd')
  },function(d){if(d.code==0)loadTab();else alert(d.msg)})
}
function editNotice(id){
  fetch('/admin/api/notice_get?id='+id).then(function(r){return r.json()}).then(function(d){
    if(d.code!==0){alert(d.msg);return}
    var g=function(i){return document.getElementById(i)};
    g('ntId').value=d.n.id||'';g('ntTitle').value=d.n.title||'';g('ntContent').value=d.n.content||'';
    g('ntLevel').value=d.n.level||'normal';g('ntTargetType').value=d.n.target_type||'all';
    g('ntTargetValue').value=d.n.target_value||'';g('ntStart').value=d.n.start_at||'';g('ntEnd').value=d.n.end_at||'';
    g('ntTitle').scrollIntoView({behavior:'smooth',block:'center'});
  })
}
function resetNotice(){['ntId','ntTitle','ntContent','ntTargetValue','ntStart','ntEnd'].forEach(function(i){var e=document.getElementById(i);if(e)e.value=''});
  document.getElementById('ntLevel').value='normal';document.getElementById('ntTargetType').value='all';}
function toggleNotice(id,s){api('/admin/api/notice_toggle',{id:id,enabled:s},loadTab)}
function delNotice(id){if(confirm('确定删除这条提示?'))api('/admin/api/notice_del',{id:id},loadTab)}
function delNoticeAck(id){if(confirm('清空该提示的已读回执? 清空后所有用户会重新看到它。'))api('/admin/api/notice_ack_clear',{id:id},loadTab)}
function saveNoticeSetting(){
  var v=document.getElementById('expireDays');if(!v)return;
  api('/admin/api/notice_setting',{key:'acct_expire_warn_days',value:v.value},function(d){if(d.code==0){alert('已保存');loadTab()}else alert(d.msg)})
}

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
    rows = db_execute("SELECT id,account_name,tq_username,status,expiry,product_type,expire_checked_at "
                      "FROM tq_accounts ORDER BY id")
    h = '<div class="form-row"><input id="accName" placeholder="账户别名"><input id="accUser" placeholder="天勤用户名"><input id="accPw" type="password" placeholder="天勤密码"><button class="btn-primary" onclick="addAcc()">新增</button></div>'
    h += ('<div style="font-size:14px;color:var(--muted);margin:6px 0 2px">'
          '到期时间由后台每 5 分钟从天勤拉取写入；剩余 ≤ 阈值(默认3天, 可配置)的账户，'
          '该账户所属用户下次登录会收到提醒。</div>')
    h += '<table><tr><th>ID</th><th>别名</th><th>天勤账号</th><th>版本</th><th>到期时间</th><th>剩余</th><th>状态</th><th>操作</th></tr>'
    now = datetime.now()
    for r in rows:
        aid, name, uname, status, expiry, ptype = r[0], r[1], r[2], r[3], r[4], r[5] or ''
        checked = r[6].strftime('%m-%d %H:%M') if r[6] else '—'
        if expiry is None:
            exp_s, left_s, left_cls = '<span class="yellow">未探测</span>', '—', ''
        else:
            exp_s = expiry.strftime('%Y-%m-%d %H:%M')
            days = (expiry - now).days
            if expiry <= now:
                left_s, left_cls = '已过期', 'red'
            elif days <= 3:
                left_s, left_cls = f'{days} 天', 'red'
            elif days <= 15:
                left_s, left_cls = f'{days} 天', 'yellow'
            else:
                left_s, left_cls = f'{days} 天', 'green'
        st = ('<span class="green">正常</span>' if status else '<span class="red">禁用</span>')
        if expiry is not None and expiry <= now:
            st = '<span class="red">已过期(自动停用)</span>'
        h += (f'<tr><td>{aid}</td><td>{name}</td><td>{uname}</td>'
              f'<td>{ptype or "-"}</td><td>{exp_s}</td>'
              f'<td class="{left_cls}" title="最后检查 {checked}">{left_s}</td>'
              f'<td>{st}</td>'
              f'<td><button onclick="toggleAcc({aid},{0 if status else 1})">{"禁用" if status else "启用"}</button></td></tr>')
    h += '</table>'
    return jsonify({'code':0,'html':h})

# ---- 管理API: 登录提示中心 ----
def _nt_html_esc(s):
    return (str(s or '').replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;'))


@app.route('/admin/api/notices')
@admin_required
def admin_notices():
    warn_days = get_acct_expire_warn_days()
    h = ('<div style="background:#0d1626;border:1px solid var(--border);border-radius:10px;padding:14px 16px;margin-bottom:16px">'
         '<div style="font-weight:700;margin-bottom:8px">⚙️ 账户到期自动提醒</div>'
         '<div class="form-row" style="margin:0">'
         '<span style="color:var(--muted)">账户到期前</span>'
         f'<input id="expireDays" type="number" min="0" max="90" value="{warn_days}" style="width:90px">'
         '<span style="color:var(--muted)">天开始登录提醒（0=关闭该提醒）</span>'
         '<button class="btn-primary" onclick="saveNoticeSetting()">保存</button></div>'
         '<div style="font-size:13px;color:var(--muted);margin-top:8px;line-height:1.8">'
         '这是系统自动类型，内容按实际情况生成（带账户名、剩余天数、到期时间），无需在此维护。<br>'
         '用户<b>每次登录都会提醒</b>，直到续费（关掉只关当次）；<b>账户已经过期的不再提醒</b>。续费后再次临近到期会重新提醒。</div></div>')

    h += ('<div style="font-weight:700;margin-bottom:8px">📢 提示内容</div>'
          '<div class="form-row">'
          '<input id="ntId" type="hidden">'
          '<input id="ntTitle" placeholder="标题" style="width:240px">'
          '<select id="ntLevel" title="重要=每次登录都弹, 直到处理为止; 普通=用户关闭一次后不再弹">'
          '<option value="normal">普通(关闭一次不再弹)</option>'
          '<option value="important">重要(每次登录都弹)</option></select>'
          '<select id="ntTargetType"><option value="all">全部用户</option><option value="role">按角色</option><option value="user">指定用户</option></select>'
          '<input id="ntTargetValue" placeholder="角色key/用户名(逗号分隔)" style="width:220px">'
          '<input id="ntStart" placeholder="生效开始 2026-09-12 00:00" style="width:190px">'
          '<input id="ntEnd" placeholder="生效结束(空=长期)" style="width:180px">'
          '</div>'
          '<div class="form-row">'
          '<textarea id="ntContent" placeholder="正文内容(支持换行)" style="width:520px;height:70px"></textarea>'
          '<button class="btn-primary" onclick="saveNotice()">保存</button>'
          '<button onclick="resetNotice()">清空/新建</button></div>')

    h += '<hr><table><tr><th>ID</th><th>级别</th><th>标题</th><th>投放对象</th><th>有效期</th><th>展示</th><th>已读</th><th>状态</th><th>操作</th></tr>'
    rows = db_execute("SELECT id,title,level,enabled,target_type,target_value,start_at,end_at,hit_count "
                      "FROM t_login_notice ORDER BY (level='important') DESC, id DESC")
    for r in rows:
        nid, title, level, enabled = r[0], r[1], r[2], r[3]
        ttype, tval = r[4], r[5] or ''
        s_at, e_at, hits = r[6], r[7], r[8] or 0
        if ttype == 'all':
            tgt = '全部用户'
        elif ttype == 'role':
            tgt = f'角色: {_nt_html_esc(tval)}'
        else:
            tgt = f'用户: {_nt_html_esc(tval)}'
        vp = (s_at.strftime('%m-%d %H:%M') if s_at else '立即') + ' ~ ' + (e_at.strftime('%m-%d %H:%M') if e_at else '长期')
        lvl = ('<span class="badge badge-admin">重要</span>' if level == 'important'
               else '<span class="badge badge-use">普通</span>')
        acks = db_one("SELECT COUNT(*) FROM t_login_notice_ack WHERE notice_id=%s", (nid,))[0]
        st = '<span class="green">生效中</span>' if enabled else '<span class="red">已下架</span>'
        h += (f'<tr><td>{nid}</td><td>{lvl}</td><td>{_nt_html_esc(title)}</td><td>{tgt}</td><td>{vp}</td>'
              f'<td>{hits}</td><td>{acks}</td><td>{st}</td>'
              f'<td><button onclick="editNotice({nid})">编辑</button>'
              f'<button onclick="toggleNotice({nid},{0 if enabled else 1})">{"下架" if enabled else "启用"}</button>'
              f'<button onclick="delNoticeAck({nid})">清已读</button>'
              f'<button class="btn-danger" onclick="delNotice({nid})">删除</button></td></tr>')
    h += '</table>'
    h += ('<div style="font-size:13px;color:var(--muted);margin-top:12px;line-height:1.9">'
          '· <b>重要</b>：每次登录都会弹，用户点"×/我知道了"只关掉当次；只有当事项本身解决'
          '或在这里"下架/删除"后才彻底消失。<br>'
          '· <b>普通</b>：用户关闭一次后即永久不再弹出（按用户记回执）；点"清已读"可让所有人重新看到。<br>'
          '· <b>账户即将到期</b>属系统自动类型（上方阈值控制），内容自动生成，不在下表里，也无需维护。</div>')
    return jsonify({'code':0,'html':h})


@app.route('/admin/api/notice_get')
@admin_required
def admin_notice_get():
    nid = request.args.get('id','')
    row = db_one("SELECT id,title,content,level,target_type,target_value,start_at,end_at "
                 "FROM t_login_notice WHERE id=%s", (nid,))
    if not row:
        return jsonify({'code':-1,'msg':'提示不存在'})
    fmt = lambda x: x.strftime('%Y-%m-%d %H:%M') if x else ''
    return jsonify({'code':0,'n':{
        'id': row[0], 'title': row[1], 'content': row[2] or '', 'level': row[3],
        'target_type': row[4] or 'all', 'target_value': row[5] or '',
        'start_at': fmt(row[6]), 'end_at': fmt(row[7]),
    }})


@app.route('/admin/api/notice_save', methods=['POST'])
@admin_required
def admin_notice_save():
    d = request.get_json(force=True)
    title = (d.get('title') or '').strip()
    if not title:
        return jsonify({'code':-1,'msg':'标题不能为空'})
    level = d.get('level') if d.get('level') in ('important','normal') else 'normal'
    ttype = d.get('target_type') if d.get('target_type') in ('all','role','user') else 'all'
    tval = (d.get('target_value') or '').strip()
    start = (d.get('start_at') or '').strip() or None
    end = (d.get('end_at') or '').strip() or None
    content = d.get('content') or ''
    nid = d.get('id')
    if nid:
        db_execute("UPDATE t_login_notice SET title=%s,content=%s,level=%s,target_type=%s,target_value=%s,"
                   "start_at=%s,end_at=%s WHERE id=%s",
                   (title, content, level, ttype, tval, start, end, nid))
    else:
        db_execute("INSERT INTO t_login_notice (title,content,level,target_type,target_value,start_at,end_at) "
                   "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                   (title, content, level, ttype, tval, start, end))
    return jsonify({'code':0})


@app.route('/admin/api/notice_toggle', methods=['POST'])
@admin_required
def admin_notice_toggle():
    d = request.get_json(force=True)
    db_execute("UPDATE t_login_notice SET enabled=%s WHERE id=%s",
               (1 if d.get('enabled') else 0, d.get('id')))
    return jsonify({'code':0})


@app.route('/admin/api/notice_del', methods=['POST'])
@admin_required
def admin_notice_del():
    nid = request.get_json(force=True).get('id')
    db_execute("DELETE FROM t_login_notice WHERE id=%s", (nid,))
    db_execute("DELETE FROM t_login_notice_ack WHERE notice_id=%s", (nid,))
    return jsonify({'code':0})


@app.route('/admin/api/notice_ack_clear', methods=['POST'])
@admin_required
def admin_notice_ack_clear():
    nid = request.get_json(force=True).get('id')
    db_execute("DELETE FROM t_login_notice_ack WHERE notice_id=%s", (nid,))
    return jsonify({'code':0})


@app.route('/admin/api/notice_setting', methods=['POST'])
@admin_required
def admin_notice_setting():
    d = request.get_json(force=True)
    k = (d.get('key') or '').strip()
    if k != 'acct_expire_warn_days':
        return jsonify({'code':-1,'msg':'不支持的设置项'})
    try:
        v = max(0, min(90, int(d.get('value'))))
    except Exception:
        return jsonify({'code':-1,'msg':'请输入 0~90 的整数'})
    set_setting(k, v, '账户到期前N天开始登录提醒')
    return jsonify({'code':0})

@app.route('/admin/api/modules')
@admin_required
def admin_modules():
    users = db_execute("SELECT id,username FROM users WHERE status=1 ORDER BY id")
    opts = ''.join('<option value="{}">{}</option>'.format(u[0], u[1]) for u in users)
    h = '<div class="form-row"><select id="permUser"><option value="">选择用户</option>' + opts + '</select><button class="btn-primary" onclick="loadUserPerms()">查看权限</button></div><div id="permResult"></div>'
    return jsonify({'code':0,'html':h})

# ---- 管理API: 模块权限 ----

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
    """绑定新天勤账户: 入库后立刻用天勤 auth 接口验证有效性, 写回权威到期时间/版本;
    验证有效则 status=1(纳入有效账户/同步缓存), 验证失败则 status=0 标记待修。
    stock_app 的同步账户缓存刷新线程会周期性发现新增的有效账户并加入缓存列表、唤醒暂停的下载。"""
    d = request.get_json(force=True)
    name, user, pwd = d.get('name',''), d.get('user',''), d.get('pass','')
    if not name or not user or not pwd:
        return jsonify({'code':-1,'msg':'账户名/用户名/密码均必填'})
    cur = db_execute("SELECT 1 FROM tq_accounts WHERE tq_username=%s", (user,))
    if cur:
        return jsonify({'code':-1,'msg':'该天勤用户名已存在'})
    db_execute("INSERT INTO tq_accounts (account_name,tq_username,tq_password) VALUES (%s,%s,%s)",
               (name, user, encrypt_secret(pwd)))
    new_id = db_one("SELECT id FROM tq_accounts WHERE tq_username=%s", (user,))[0]
    try:
        exp, ptype, days = _tq_auth_expiry(user, pwd)
        exp_str = exp.strftime("%Y-%m-%d %H:%M:%S") if exp else None
        expired = is_account_expired(exp)
        db_execute("UPDATE tq_accounts SET expiry=%s,product_type=%s,status=1,expire_checked_at=NOW() WHERE id=%s",
                   (exp_str, ptype, new_id))
        if expired:
            return jsonify({'code':0,'msg':f'账户已添加: 试用/专业已到期(到期={exp_str}, {ptype}), 但免费行情(期货/期权/指数)仍可使用, 付费数据需续费'})
        return jsonify({'code':0,'msg':f'账户已添加并验证有效(到期={exp_str}, {ptype}, 剩余{days}天), 已纳入有效账户'})
    except Exception as e:
        # 认证失败(密码错/网络): 保留账户但标记停用, 等待管理员修正
        db_execute("UPDATE tq_accounts SET status=0, expire_checked_at=NOW() WHERE id=%s", (new_id,))
        return jsonify({'code':-1,'msg':f'天勤验证失败: {str(e)[:80]} (已入库并标记停用, 请检查密码)'}), 400

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

@app.route('/admin/api/register_code')
@admin_required
def admin_register_code():
    """展示当前子服务注册码(仅管理员), 便于发给合作方接入。"""
    return jsonify({'code':0, 'enabled':bool(REGISTER_CODE),
                    'register_code':REGISTER_CODE, 'source':REGISTER_CODE_SRC})


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
    if REGISTER_CODE:
        print(f"[注册码] 准入校验已启用 (来源: {REGISTER_CODE_SRC})")
    else:
        print("[注册码] 警告: 未启用(register_code 为空) —— 任何服务都能注册进来, 仅本地开发可接受")
    # 2026-10-09: 打印密钥来源, 便于确认"重启后 session 是否仍有效"
    print(f"[会话密钥] 已加载 (来源: {SECRET_KEY_SRC})")
    init_db()
    migrate_tq_passwords()
    migrate_tq_accounts_expiry()
    threading.Thread(target=heartbeat_checker, daemon=True).start()
    print(f"[心跳] 已启动 (间隔{HEARTBEAT_INTERVAL}s)")
    threading.Thread(target=account_expiry_checker, daemon=True).start()
    print(f"[账户到期] 定时刷新已启动 (间隔{ACCOUNT_EXPIRY_INTERVAL}s)")
    app.run(host='0.0.0.0', port=CENTER_PORT, debug=False, use_reloader=False)

if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        raise
    except Exception as _boot_err:
        # 兜底: 把 PyInstaller 的"裸崩溃(PYI-xxxx ERROR + 英文栈)"变成可读中文提示。
        import sys as _sys
        import traceback as _tb
        print(f"[启动] 启动失败: {_boot_err}", flush=True)
        if _boot_err.__class__.__module__.split('.')[0] == 'pymysql':
            print(_db_hint(), flush=True)
        _tb.print_exc()
        try:
            # 双击 exe 时留住控制台窗口, 让用户看得到原因; 由 launcher 拉起时无控制台, 直接跳过。
            if _sys.stdin and _sys.stdin.isatty():
                input('按回车键退出…')
        except Exception:
            pass
        _sys.exit(1)