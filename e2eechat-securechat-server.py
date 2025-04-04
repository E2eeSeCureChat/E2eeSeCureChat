import asyncio
import json
import sqlite3
import ssl
import os
import random
import hashlib
import time
import smtplib
from email.mime.text import MIMEText
from passlib.hash import argon2
from cryptography.fernet import Fernet
import logging
from threading import Lock

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# 配置文件路径
DB_FILE = '/root/run/users.db'
CERT_FILE = '/etc/letsencrypt/live/chat.e2eechat.com/fullchain.pem'  # 使用 fullchain.pem
KEY_FILE = '/etc/letsencrypt/live/chat.e2eechat.com/privkey.pem'    # 使用 privkey.pem

# SMTP 配置（从环境变量读取）
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USER = os.getenv('SMTP_USER', 'securechat.login@gmail.com')
SMTP_PASS = os.getenv('SMTP_PASS', 'dnmu qcta ggkb phgk')  # 替换为实际应用密钥或环境变量

# 标准2048位 DH 参数（与客户端一致）
DH_P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
           "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
           "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
           "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
           "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
           "FFFFFFFFFFFFFFFF", 16)
DH_G = 2

# 存储验证码的临时字典 {email: {"code": code, "time_sent": time}}
email_codes = {}
email_codes_lock = Lock()  # 线程安全锁

# 生成 Fernet 密钥用于加密电邮
fernet_key = Fernet.generate_key()
cipher_suite = Fernet(fernet_key)

### 数据库相关函数

def init_db():
    """初始化数据库，创建 users、friends、groups 和 group_members 表"""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            encrypted_email TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL
        )
        """)
        c.execute("""
        CREATE TABLE IF NOT EXISTS friends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user1 TEXT NOT NULL,
            user2 TEXT NOT NULL,
            UNIQUE(user1, user2)
        )
        """)
        c.execute("""
        CREATE TABLE IF NOT EXISTS groups (
            group_id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_name TEXT NOT NULL,
            creator TEXT NOT NULL
        )
        """)
        c.execute("""
        CREATE TABLE IF NOT EXISTS group_members (
            group_id INTEGER,
            username TEXT,
            PRIMARY KEY (group_id, username),
            FOREIGN KEY (group_id) REFERENCES groups(group_id)
        )
        """)
        conn.commit()
    logger.info("[数据库] 已初始化所有表")

def encrypt_email(email):
    """使用 SHA-256 对邮箱进行哈希加密"""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(email.encode('utf-8'))  # 将邮箱转换为字节串并加密
    return sha256_hash.hexdigest()

def decrypt_email(encrypted_email):
    """SHA-256 不可解密，所以此函数可以删除或用于验证"""
    pass  # 不需要解密，只验证哈希匹配即可

def register_user(username, password, email, public_key, code):
    """注册用户，验证验证码并存储用户信息"""
    success, message = verify_email_code(email, code)
    if not success:
        return False, message
    encrypted_email = encrypt_email(email)
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username=? OR encrypted_email=?", (username, encrypted_email))
        if c.fetchone():
            return False, "用户名或邮箱已存在"
        pwd_hash = argon2.hash(password)
        c.execute("INSERT INTO users(username, password_hash, encrypted_email, public_key) VALUES(?, ?, ?, ?)",
                  (username, pwd_hash, encrypted_email, public_key))
        conn.commit()
    #logger.info(f"[注册] 用户 {username} 注册成功")
    return True, ""

def check_login(username, password):
    """验证登录，兼容旧 PBKDF2 哈希并迁移到 Argon2"""
    from passlib.hash import pbkdf2_sha256
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT password_hash FROM users WHERE username=?", (username,))
        row = c.fetchone()
        if not row:
            return False
        stored_hash = row[0]
        try:
            if argon2.verify(password, stored_hash):
                return True
        except Exception:
            if pbkdf2_sha256.verify(password, stored_hash):
                new_hash = argon2.hash(password)
                c.execute("UPDATE users SET password_hash=? WHERE username=?", (new_hash, username))
                conn.commit()
                #logger.info(f"[登录] 用户 {username} 密码已从 PBKDF2 迁移到 Argon2")
                return True
    return False

def update_public_key(username, public_key):
    """更新用户的公钥"""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET public_key=? WHERE username=?", (public_key, username))
        conn.commit()
    #logger.debug(f"[公钥] 用户 {username} 的公钥已更新")

def check_user_email(username, email):
    """验证用户名和邮箱是否匹配，或仅检查邮箱未注册（注册场景）"""
    #print("5")
    if not email:
        return False
    #print("6")
    encrypted_email = encrypt_email(email)  # 使用 SHA-256 哈希加密邮箱
    #print(f"[调试] 加密后的邮箱: {encrypted_email}")  # 打印加密后的邮箱

    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        if username:  # 重置密码场景
            c.execute("SELECT id FROM users WHERE username=? AND encrypted_email=?", (username, encrypted_email))
            result = c.fetchone()
            if result:
                #print(f"[调试] 用户名和加密邮箱匹配: {result}")
                return True
            else:
                #print("[调试] 用户名和加密邮箱不匹配")
                return False
        else:  # 注册场景
            c.execute("SELECT id FROM users WHERE encrypted_email=?", (encrypted_email,))
            result = c.fetchone()
            if not result:
                #print("[调试] 邮箱未注册")
                return True  # 邮箱未注册
            else:
                #print("[调试] 邮箱已注册")
                return False  # 邮箱已注册


def reset_password(username, email, new_password, code):
    """重置用户密码，验证验证码"""
    success, message = verify_email_code(email, code)
    if not success:
        return False, message
    encrypted_email = encrypt_email(email)
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username=? AND encrypted_email=?", (username, encrypted_email))
        if not c.fetchone():
            return False, "用户名或邮箱不匹配"
        new_pwd_hash = argon2.hash(new_password)
        c.execute("UPDATE users SET password_hash=? WHERE username=?", (new_pwd_hash, username))
        conn.commit()
    #logger.info(f"[重置密码] 用户 {username} 密码已重置")
    return True, ""

def search_users(keyword):
    """搜索用户"""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE username LIKE ?", ('%'+keyword+'%',))
        rows = c.fetchall()
    return [r[0] for r in rows]

def add_friend_db(user, friend_name):
    """建立好友关系"""
    if user == friend_name:
        return False, "不能添加自己为好友"
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username=?", (friend_name,))
        if not c.fetchone():
            return False, "对方用户不存在"
        user1, user2 = sorted([user, friend_name])
        c.execute("SELECT id FROM friends WHERE user1=? AND user2=?", (user1, user2))
        if c.fetchone():
            return False, "已是好友关系"
        c.execute("INSERT INTO friends(user1, user2) VALUES(?, ?)", (user1, user2))
        conn.commit()
    #logger.info(f"[好友] {user} 添加 {friend_name} 为好友")
    return True, None

def list_friends_db(username):
    """返回好友列表"""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT user1, user2 FROM friends WHERE user1=? OR user2=?", (username, username))
        rows = c.fetchall()
    friend_list = [u1 if u1 != username else u2 for u1, u2 in rows]
    return friend_list

def create_group_db(group_name, creator, members):
    """创建群聊"""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO groups (group_name, creator) VALUES (?, ?)", (group_name, creator))
        group_id = c.lastrowid
        for member in members:
            c.execute("INSERT OR IGNORE INTO group_members (group_id, username) VALUES (?, ?)", (group_id, member))
        conn.commit()
    #logger.info(f"[群聊] {creator} 创建了群聊 {group_name} (ID: {group_id})")
    return group_id

def list_groups_db(username):
    """返回用户所在的群聊列表"""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        try:
            c.execute("""
            SELECT g.group_id, g.group_name, g.creator
            FROM groups g
            JOIN group_members gm ON g.group_id = gm.group_id
            WHERE gm.username = ?
            """, (username,))
            rows = c.fetchall()
        except sqlite3.OperationalError as e:
            logger.error(f"[数据库错误] 查询群聊列表失败: {e}")
            return []
    return [{"group_id": row[0], "group_name": row[1], "creator": row[2]} for row in rows]

def get_group_members_with_public_keys(group_id):
    """返回群聊成员及其公钥"""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("""
        SELECT gm.username, u.public_key
        FROM group_members gm
        JOIN users u ON gm.username = u.username
        WHERE gm.group_id=?
        """, (group_id,))
        rows = c.fetchall()
    return {row[0]: row[1] for row in rows}

def get_group_creator(group_id):
    """获取群聊创建者"""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT creator FROM groups WHERE group_id=?", (group_id,))
        row = c.fetchone()
    return row[0] if row else None

def get_group_info(group_id):
    """获取群聊信息：群聊名和创建者"""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT group_name, creator FROM groups WHERE group_id=?", (group_id,))
        row = c.fetchone()
    return (row[0], row[1]) if row else (None, None)

def delete_friend_db(user, friend_name):
    """删除好友关系"""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        user1, user2 = sorted([user, friend_name])
        c.execute("DELETE FROM friends WHERE user1=? AND user2=?", (user1, user2))
        changes = conn.total_changes
        conn.commit()
    if changes > 0:
        pass
        #logger.info(f"[好友] {user} 删除了好友 {friend_name}")
    return changes > 0

def leave_group_db(username, group_id):
    """退群操作，群主不允许退出"""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT creator FROM groups WHERE group_id=?", (group_id,))
        row = c.fetchone()
        if row and row[0] == username:
            return False, "群主不能退出群聊"
        c.execute("DELETE FROM group_members WHERE group_id=? AND username=?", (group_id, username))
        if c.rowcount == 0:
            return False, "您不在该群聊中"
        conn.commit()
    logger.info(f"[群聊] {username} 退出了群聊 {group_id}")
    return True, None

def invite_to_group_db(group_id, inviter, friend_name):
    """邀请好友加入群聊"""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username=?", (friend_name,))
        if not c.fetchone():
            return False, "邀请的用户不存在"
        c.execute("SELECT * FROM group_members WHERE group_id=? AND username=?", (group_id, friend_name))
        if c.fetchone():
            return False, "用户已在群聊中"
        c.execute("INSERT INTO group_members (group_id, username) VALUES (?, ?)", (group_id, friend_name))
        conn.commit()
    logger.info(f"[群聊] {inviter} 邀请 {friend_name} 加入群聊 {group_id}")
    return True, None

### 邮箱验证相关函数

def send_email_code(email):
    """发送验证码到邮箱"""
    if not email:
        return False, "邮箱地址为空"
    
    code = str(random.randint(100000, 999999))
    with email_codes_lock:
        email_codes[email] = {"code": code, "time_sent": time.time()}
    
    msg = MIMEText(f"""
    尊敬的用户:

    您好!这是来自 SeCureChat 的验证邮件。

    您的验证码为: {code}

    请注意:
    - 验证码有效期为 1 分钟
    - 请勿将验证码泄露给他人
    - 如非本人操作,请忽略此邮件

    此致
    SeCureChat 团队
    """)
    msg["From"] = SMTP_USER
    msg["To"] = email
    msg['Subject'] = 'SeCureChat - 账号验证码'

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, email, msg.as_string())
        logger.info(f"[邮件] 验证码已发送至邮箱")
        return True, "验证码已发送"
    except smtplib.SMTPException as e:
        logger.error(f"[邮件错误] 发送至邮箱失败: {e}")
        return False, f"邮件发送失败: {e}"

def verify_email_code(email, code):
    """验证邮箱验证码"""
    with email_codes_lock:
        if email not in email_codes:
            return False, "未发送验证码"
        info = email_codes[email]
        if time.time() - info["time_sent"] > 60:
            del email_codes[email]
            return False, "验证码已过期"
        if code == info["code"]:
            del email_codes[email]
            logger.debug(f"[验证码] 邮箱验证成功")
            return True, "验证成功"
        return False, "验证码错误"

### 服务器类

class ChatServer:
    def __init__(self, host='0.0.0.0', port=8443):
        self.host = host
        self.port = port
        self.online_users = {}  # { username: (reader, writer) }
        self.chat_sessions = {}  # { (A, B): True }

    def start(self):
        """启动服务器"""
        init_db()
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        loop = asyncio.get_event_loop()
        server_coro = asyncio.start_server(self.handle_client, self.host, self.port, ssl=ssl_ctx)
        server = loop.run_until_complete(server_coro)
        logger.info(f"[服务器] TLS聊天服务器已启动，监听 {self.host}:{self.port}")
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            server.close()
            loop.run_until_complete(server.wait_closed())
            loop.close()
            logger.info("[服务器] 已关闭")

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        logger.info(f"[连接] 来自 地址")
        username = None
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                line = line.decode('utf-8', errors='ignore').strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError as e:
                    logger.warning(f"[解析错误] 无效的 JSON 数据: {line}, 错误: {e}")
                    continue
                action = msg.get("action")
                data = msg.get("data", {})
                #logger.debug(f"[收到] {action}: {data}")

                if action == "check_user_email":
                    user = data.get("username", "")
                    email = data.get("email")
                    if email:
                        print("1")
                        if user:
                            print("2")
                            if check_user_email(user, email):
                                print("3")
                                success, message = send_email_code(email)
                                await self.send_json(writer, {"action": "check_user_email_result", "data": {"ok": success, "error": message if not success else ""}})
                            else:
                                await self.send_json(writer, {"action": "check_user_email_result", "data": {"ok": False, "error": "用户名或邮箱不匹配"}})
                        else:
                            if check_user_email("", email):
                                success, message = send_email_code(email)
                                await self.send_json(writer, {"action": "check_user_email_result", "data": {"ok": success, "error": message if not success else ""}})
                            else:
                                await self.send_json(writer, {"action": "check_user_email_result", "data": {"ok": False, "error": "邮箱已注册"}})
                    else:
                        await self.send_json(writer, {"action": "check_user_email_result", "data": {"ok": False, "error": "邮箱参数缺失"}})

                elif action == "reset_password":
                    user = data.get("username")
                    email = data.get("email")
                    new_pwd = data.get("new_password")
                    code = data.get("code")
                    if user and email and new_pwd and code:
                        success, error = reset_password(user, email, new_pwd, code)
                        await self.send_json(writer, {"action": "reset_password_result", "data": {"ok": success, "error": error}})
                    else:
                        await self.send_json(writer, {"action": "reset_password_result", "data": {"ok": False, "error": "参数缺失"}})

                elif action == "register":
                    user = data.get("username")
                    pwd = data.get("password")
                    email = data.get("email")
                    pubkey = data.get("public_key")
                    code = data.get("code")
                    if user and pwd and email and pubkey and code:
                        success, error = register_user(user, pwd, email, pubkey, code)
                        await self.send_json(writer, {"action": "register_result", "data": {"ok": success, "error": error}})
                    else:
                        await self.send_json(writer, {"action": "register_result", "data": {"ok": False, "error": "参数缺失"}})

                elif action == "login":
                    user = data.get("username")
                    pwd = data.get("password")
                    pubkey = data.get("public_key")
                    if user and pwd and pubkey and check_login(user, pwd):
                        if user in self.online_users:
                            await self.send_json(writer, {"action": "login_result", "data": {"ok": False, "error": "用户已在线"}})
                        else:
                            username = user
                            self.online_users[username] = (reader, writer)
                            update_public_key(username, pubkey)
                            await self.send_json(writer, {"action": "login_result", "data": {"ok": True}})
                            logger.info(f"[登录] 用户 {username} 已上线")
                    else:
                        await self.send_json(writer, {"action": "login_result", "data": {"ok": False, "error": "用户名或密码错误"}})

                elif action == "search":
                    if not username:
                        continue
                    keyword = data.get("keyword", "")
                    found_list = search_users(keyword)
                    result_list = [{"username": u, "online": u in self.online_users} for u in found_list]
                    await self.send_json(writer, {"action": "search_result", "data": {"results": result_list}})

                elif action == "chat_request":
                    if not username:
                        continue
                    target = data.get("target")
                    if target in self.online_users:
                        t_reader, t_writer = self.online_users[target]
                        await self.send_json(t_writer, {"action": "chat_invite", "data": {"from_user": username}})
                    else:
                        await self.send_json(writer, {"action": "chat_request_fail", "data": {"error": "对方不在线或不存在"}})

                elif action == "chat_response":
                    if not username:
                        continue
                    from_user = data.get("from_user")
                    accept = data.get("accept", False)
                    if from_user in self.online_users:
                        f_reader, f_writer = self.online_users[from_user]
                        if accept:
                            key = tuple(sorted([username, from_user]))
                            self.chat_sessions[key] = True
                            await self.send_json(f_writer, {"action": "chat_accepted", "data": {"from_user": username}})
                        else:
                            await self.send_json(f_writer, {"action": "chat_declined", "data": {"from_user": username}})

                elif action == "dh_exchange":
                    if not username:
                        continue
                    target = data.get("target")
                    if target in self.online_users:
                        key = tuple(sorted([username, target]))
                        if key in self.chat_sessions:
                            t_reader, t_writer = self.online_users[target]
                            await self.send_json(t_writer, {"action": "dh_exchange", "data": {"from_user": username, "public_key": data.get("public_key")}})

                elif action == "send_message":
                    if not username:
                        continue
                    target = data.get("target")
                    if target in self.online_users:
                        key = tuple(sorted([username, target]))
                        if key in self.chat_sessions:
                            t_reader, t_writer = self.online_users[target]
                            await self.send_json(t_writer, {
                                "action": "receive_message",
                                "data": {
                                    "from_user": username,
                                    "ciphertext": data.get("ciphertext"),
                                    "nonce": data.get("nonce"),
                                    "tag": data.get("tag")
                                }
                            })

                elif action == "add_friend":
                    if not username:
                        continue
                    friend_name = data.get("friend_name")
                    if friend_name:
                        ok, err = add_friend_db(username, friend_name)
                        await self.send_json(writer, {"action": "add_friend_result", "data": {"ok": ok, "error": err if not ok else ""}})

                elif action == "list_friends":
                    if not username:
                        continue
                    friend_list = list_friends_db(username)
                    res = [{"username": f, "online": f in self.online_users} for f in friend_list]
                    await self.send_json(writer, {"action": "list_friends_result", "data": {"friends": res}})

                elif action == "create_group":
                    if not username:
                        continue
                    group_name = data.get("group_name")
                    members = data.get("members", [])
                    if group_name and members:
                        group_id = create_group_db(group_name, username, members)
                        for member in members:
                            if member in self.online_users:
                                m_reader, m_writer = self.online_users[member]
                                await self.send_json(m_writer, {
                                    "action": "group_invite",
                                    "data": {"group_id": group_id, "group_name": group_name, "from_user": username}
                                })
                        await self.send_json(writer, {"action": "create_group_result", "data": {"ok": True, "group_id": group_id}})
                    else:
                        await self.send_json(writer, {"action": "create_group_result", "data": {"ok": False, "error": "参数错误"}})

                elif action == "invite_to_group":
                    if not username:
                        continue
                    group_id = data.get("group_id")
                    friend_name = data.get("friend_name")
                    if group_id and friend_name:
                        success, error_msg = invite_to_group_db(group_id, username, friend_name)
                        if success:
                            group_name, _ = get_group_info(group_id)
                            if friend_name in self.online_users:
                                m_reader, m_writer = self.online_users[friend_name]
                                await self.send_json(m_writer, {
                                    "action": "group_invite",
                                    "data": {"group_id": group_id, "group_name": group_name, "from_user": username}
                                })
                        await self.send_json(writer, {"action": "invite_to_group_result", "data": {"ok": success, "error": error_msg if not success else ""}})

                elif action == "send_group_message":
                    if not username:
                        continue
                    group_id = data.get("group_id")
                    ciphertext = data.get("ciphertext")
                    nonce = data.get("nonce")
                    tag = data.get("tag")
                    if group_id and ciphertext and nonce and tag:
                        members = get_group_members_with_public_keys(group_id)
                        for member in members:
                            if member != username and member in self.online_users:
                                m_reader, m_writer = self.online_users[member]
                                await self.send_json(m_writer, {
                                    "action": "receive_group_message",
                                    "data": {
                                        "group_id": group_id,
                                        "from_user": username,
                                        "ciphertext": ciphertext,
                                        "nonce": nonce,
                                        "tag": tag
                                    }
                                })

                elif action == "list_groups":
                    if not username:
                        continue
                    groups = list_groups_db(username)
                    await self.send_json(writer, {"action": "list_groups_result", "data": {"groups": groups}})

                elif action == "get_group_members":
                    if not username:
                        continue
                    group_id = data.get("group_id")
                    creator = get_group_creator(group_id)
                    if not creator:
                        await self.send_json(writer, {"action": "group_members_result", "data": {"ok": False, "error": "群聊不存在"}})
                    elif creator != username:
                        await self.send_json(writer, {"action": "group_members_result", "data": {"ok": False, "error": "仅群主可获取成员列表"}})
                    else:
                        members = get_group_members_with_public_keys(group_id)
                        await self.send_json(writer, {"action": "group_members_result", "data": {"group_id": group_id, "members": members}})

                elif action == "group_key_distribute":
                    if not username:
                        continue
                    group_id = data.get("group_id")
                    encrypted_keys = data.get("encrypted_keys", {})
                    creator = get_group_creator(group_id)
                    if not creator:
                        await self.send_json(writer, {"action": "group_key_distribute_result", "data": {"ok": False, "error": "群聊不存在"}})
                    elif creator != username:
                        await self.send_json(writer, {"action": "group_key_distribute_result", "data": {"ok": False, "error": "仅群主可分发密钥"}})
                    else:
                        logger.info(f"[群聊] {username} 分发群聊[{group_id}]密钥给 {list(encrypted_keys.keys())}")
                        for member, encrypted_key in encrypted_keys.items():
                            if member in self.online_users:
                                m_reader, m_writer = self.online_users[member]
                                await self.send_json(m_writer, {
                                    "action": "group_key_distribute",
                                    "data": {"group_id": group_id, "encrypted_key": encrypted_key}
                                })
                                logger.debug(f"[群聊] 密钥已发送给 {member}")
                        await self.send_json(writer, {"action": "group_key_distribute_result", "data": {"ok": True}})

                elif action == "delete_friend":
                    if not username:
                        continue
                    friend_name = data.get("friend_name")
                    if friend_name:
                        success = delete_friend_db(username, friend_name)
                        await self.send_json(writer, {"action": "delete_friend_result", "data": {"ok": success, "error": "" if success else "删除好友失败"}})

                elif action == "leave_group":
                    if not username:
                        continue
                    group_id = data.get("group_id")
                    if group_id:
                        success, error_msg = leave_group_db(username, group_id)
                        await self.send_json(writer, {"action": "leave_group_result", "data": {"ok": success, "error": error_msg if not success else ""}})
        except Exception as e:
            logger.error(f"[客户端错误] {addr} 处理失败: {e}", exc_info=True)
        finally:
            if username and username in self.online_users:
                del self.online_users[username]
                logger.info(f"[下线] 用户 {username} 已离线")
            writer.close()
            await writer.wait_closed()
            logger.info(f"[断开] {addr}")

    async def send_json(self, writer, msg_dict):
        """发送 JSON 消息"""
        try:
            data = (json.dumps(msg_dict) + "\n").encode('utf-8')
            writer.write(data)
            await writer.drain()
            logger.debug(f"[发送] {msg_dict}")
        except Exception as e:
            logger.error(f"[发送错误] {e}")

if __name__ == "__main__":
    server = ChatServer(host="0.0.0.0", port=8443)
    server.start()
