import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext
import asyncio
import json
import ssl
import base64
import os
import sys
import re
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.number import getRandomRange
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import threading

# DH 参数 (与服务器相同) 2048位
DH_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1 + \
       0x29024E088A67CC74020BBEA63B139B22514A08798E3404DDEF + \
       0x9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B5 + \
       0x7617CBEA1FAEE7EA4A539A77DAF8E8F4C6F5CA5F25F7205F + \
       0xB9C0C1134064D
DH_G = 2

class E2EEChatClient:
    def __init__(self, master, server_ip="chat.e2eechat.com", server_port=8443):
        self.master = master
        self.master.title("SeCureChat-V1.0")
        self.server_ip = server_ip
        self.server_port = server_port

        self.reader = None
        self.writer = None
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.username = None
        self.shared_keys = {}
        self.group_keys = {}
        self.current_chat_target = None
        self.dh_states = {}
        self.group_creators = {}
        self.private_key = None
        self.public_key = None
        self.email_sent = False

        self.history_file = "chat_history.json"
        self.chat_history = {}
        # 新增变量，用于保存聊天历史加密使用的密钥（只提示一次密码）
        self.chat_history_key = None  
        self.load_chat_history()

        self.create_initial_page()
        try:
            self.loop.run_until_complete(self.async_connect_server())
        except ConnectionError as e:
            messagebox.showerror("错误", str(e))
            raise

    def create_initial_page(self):
        for widget in self.master.winfo_children():
            widget.destroy()
        
        self.initial_frame = tk.Frame(self.master)
        self.initial_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        tk.Label(self.initial_frame, text="欢迎使用SeCureChat", font=("Arial", 16)).pack(pady=10)

        btn_register = tk.Button(self.initial_frame, text="注册", command=self.show_register_form)
        btn_register.pack(pady=5)
        btn_login = tk.Button(self.initial_frame, text="登录", command=self.show_login_form)
        btn_login.pack(pady=5)
        btn_reset_password = tk.Button(self.initial_frame, text="重置密码", command=self.show_reset_password_form)
        btn_reset_password.pack(pady=5)

    def clear_frame(self):
        for widget in self.initial_frame.winfo_children():
            widget.destroy()

    def show_register_form(self):
        self.clear_frame()
        tk.Label(self.initial_frame, text="注册", font=("Arial", 14)).pack(pady=5)

        tk.Label(self.initial_frame, text="用户名（3-20位字母数字）：").pack()
        self.reg_username_entry = tk.Entry(self.initial_frame)
        self.reg_username_entry.pack()

        tk.Label(self.initial_frame, text="密码（至少8位）：").pack()
        self.reg_password_entry = tk.Entry(self.initial_frame, show='*')
        self.reg_password_entry.pack()

        tk.Label(self.initial_frame, text="邮箱：").pack()
        self.reg_email_entry = tk.Entry(self.initial_frame)
        self.reg_email_entry.pack()

        tk.Button(self.initial_frame, text="发送验证码", command=self.send_register_code).pack(pady=5)
        self.reg_code_entry = tk.Entry(self.initial_frame)
        self.reg_code_entry.pack()

        tk.Button(self.initial_frame, text="提交注册", command=self.submit_register).pack(pady=5)
        tk.Button(self.initial_frame, text="返回", command=self.create_initial_page).pack(pady=5)

    def show_login_form(self):
        self.clear_frame()
        tk.Label(self.initial_frame, text="登录", font=("Arial", 14)).pack(pady=5)

        tk.Label(self.initial_frame, text="用户名：").pack()
        self.login_username_entry = tk.Entry(self.initial_frame)
        self.login_username_entry.pack()

        tk.Label(self.initial_frame, text="密码：").pack()
        self.login_password_entry = tk.Entry(self.initial_frame, show='*')
        self.login_password_entry.pack()

        tk.Button(self.initial_frame, text="登录", command=self.submit_login).pack(pady=5)
        tk.Button(self.initial_frame, text="返回", command=self.create_initial_page).pack(pady=5)

    def show_reset_password_form(self):
        self.clear_frame()
        tk.Label(self.initial_frame, text="重置密码", font=("Arial", 14)).pack(pady=5)

        tk.Label(self.initial_frame, text="用户名：").pack()
        self.reset_username_entry = tk.Entry(self.initial_frame)
        self.reset_username_entry.pack()

        tk.Label(self.initial_frame, text="邮箱：").pack()
        self.reset_email_entry = tk.Entry(self.initial_frame)
        self.reset_email_entry.pack()

        tk.Button(self.initial_frame, text="发送验证码", command=self.send_reset_code).pack(pady=5)
        self.reset_code_entry = tk.Entry(self.initial_frame)
        self.reset_code_entry.pack()

        tk.Label(self.initial_frame, text="新密码（至少8位）：").pack()
        self.reset_new_password_entry = tk.Entry(self.initial_frame, show='*')
        self.reset_new_password_entry.pack()

        tk.Button(self.initial_frame, text="提交重置", command=self.submit_reset_password).pack(pady=5)
        tk.Button(self.initial_frame, text="返回", command=self.create_initial_page).pack(pady=5)

    def send_register_code(self):
        email = self.reg_email_entry.get().strip()
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            messagebox.showwarning("警告", "无效的邮箱格式")
            return
        if email:
            self.email_sent = False
            print(f"调试：准备发送验证码请求，邮箱={email}")
            asyncio.run_coroutine_threadsafe(
                self.async_send({"action": "check_user_email", "data": {"username": "", "email": email}}),
                self.loop
            )
            messagebox.showinfo("提示", "正在发送验证码，请稍候...")
        else:
            messagebox.showwarning("警告", "请输入邮箱地址")

    def send_reset_code(self):
        email = self.reset_email_entry.get().strip()
        username = self.reset_username_entry.get().strip()
        print(f"调试：原始输入 - 用户名='{username}'，邮箱='{email}'")
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            messagebox.showwarning("警告", "无效的邮箱格式")
            return
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            messagebox.showwarning("警告", "无效的用户名格式")
            return
        if email and username:
            self.email_sent = False
            print(f"调试：准备发送重置验证码请求，用户名={username}，邮箱={email}")
            asyncio.run_coroutine_threadsafe(
                self.async_send({"action": "check_user_email", "data": {"username": username, "email": email}}),
                self.loop
            )
            messagebox.showinfo("提示", "正在验证并发送验证码，请稍候...")
        else:
            messagebox.showwarning("警告", "请输入用户名和邮箱地址")

    def submit_register(self):
        u = self.reg_username_entry.get().strip()
        p = self.reg_password_entry.get()
        email = self.reg_email_entry.get().strip()
        code = self.reg_code_entry.get().strip()

        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', u):
            messagebox.showerror("错误", "用户名必须为3-20位字母数字")
            return
        if len(p) < 8:
            messagebox.showerror("错误", "密码必须至少8位")
            return
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            messagebox.showerror("错误", "无效的邮箱格式")
            return

        if u and p and email and code:
            if not self.email_sent:
                messagebox.showerror("错误", "请先发送验证码")
                return
            key = RSA.generate(2048)
            self.private_key = key
            self.public_key = key.publickey()
            pubkey_pem = self.public_key.export_key().decode('utf-8')
            private_key_pem = key.export_key('PEM', passphrase=p)
            key_file = f"{u}_private_key.pem"
            try:
                with open(key_file, 'wb') as f:
                    f.write(private_key_pem)
                print(f"调试：私钥已保存到文件 {key_file}")
            except Exception as e:
                messagebox.showerror("错误", f"保存私钥到文件失败: {e}")
                return
            asyncio.run_coroutine_threadsafe(
                self.async_send({
                    "action": "register",
                    "data": {"username": u, "password": p, "email": email, "public_key": pubkey_pem, "code": code}
                }),
                self.loop
            )
        else:
            messagebox.showwarning("警告", "请填写所有字段")

    def submit_login(self):
        u = self.login_username_entry.get().strip()
        p = self.login_password_entry.get()
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', u):
            messagebox.showerror("错误", "无效的用户名格式")
            return
        if len(p) < 8:
            messagebox.showerror("错误", "密码必须至少8位")
            return
        if u and p:
            self.username = u
            key_file = f"{u}_private_key.pem"
            if os.path.exists(key_file):
                try:
                    with open(key_file, 'rb') as f:
                        self.private_key = RSA.import_key(f.read(), passphrase=p)
                    self.public_key = self.private_key.publickey()
                except Exception as e:
                    messagebox.showerror("错误", f"加载私钥失败: {e}")
                    return
            else:
                key = RSA.generate(2048)
                self.private_key = key
                self.public_key = key.publickey()
                with open(key_file, 'wb') as f:
                    f.write(key.export_key('PEM', passphrase=p))
            pubkey_pem = self.public_key.export_key().decode('utf-8')
            asyncio.run_coroutine_threadsafe(
                self.async_send({"action": "login", "data": {"username": u, "password": p, "public_key": pubkey_pem}}),
                self.loop
            )
        else:
            messagebox.showwarning("警告", "请填写用户名和密码")

    def submit_reset_password(self):
        u = self.reset_username_entry.get().strip()
        email = self.reset_email_entry.get().strip()
        code = self.reset_code_entry.get().strip()
        new_p = self.reset_new_password_entry.get()

        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', u):
            messagebox.showerror("错误", "无效的用户名格式")
            return
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            messagebox.showerror("错误", "无效的邮箱格式")
            return
        if len(new_p) < 8:
            messagebox.showerror("错误", "新密码必须至少8位")
            return

        if u and email and code and new_p:
            if not self.email_sent:
                messagebox.showerror("错误", "请先发送验证码")
                return
            asyncio.run_coroutine_threadsafe(
                self.async_send({
                    "action": "reset_password",
                    "data": {"username": u, "email": email, "new_password": new_p, "code": code}
                }),
                self.loop
            )
        else:
            messagebox.showwarning("警告", "请填写所有字段")

    def create_chat_interface(self):
        if hasattr(self, 'initial_frame'):
            self.initial_frame.destroy()
        
        self.chat_frame = tk.Frame(self.master)
        self.chat_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        frame_top = tk.Frame(self.chat_frame)
        frame_top.pack(fill=tk.X, padx=5, pady=5)

        self.btn_search = tk.Button(frame_top, text="搜索用户", command=self.search_dialog)
        self.btn_search.pack(side=tk.LEFT, padx=5)
        self.btn_add_friend = tk.Button(frame_top, text="添加好友", command=self.add_friend_dialog)
        self.btn_add_friend.pack(side=tk.LEFT, padx=5)
        self.btn_create_group = tk.Button(frame_top, text="创建群聊", command=self.create_group_dialog)
        self.btn_create_group.pack(side=tk.LEFT, padx=5)

        frame_middle = tk.Frame(self.chat_frame)
        frame_middle.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        frame_left = tk.Frame(frame_middle)
        frame_left.pack(side=tk.LEFT, fill=tk.Y)
        tk.Label(frame_left, text="我的好友").pack(anchor=tk.W)
        self.friends_listbox = tk.Listbox(frame_left, height=10, width=20)
        self.friends_listbox.pack(fill=tk.Y, expand=True)
        self.friends_listbox.bind("<Double-Button-1>", self.on_friend_double_click)
        self.btn_refresh_friends = tk.Button(frame_left, text="刷新好友列表", command=self.list_friends)
        self.btn_refresh_friends.pack(pady=5)
        self.btn_delete_friend = tk.Button(frame_left, text="删除好友", command=self.delete_friend_dialog)
        self.btn_delete_friend.pack(pady=5)

        tk.Label(frame_left, text="我的群聊").pack(anchor=tk.W)
        self.groups_listbox = tk.Listbox(frame_left, height=10, width=20)
        self.groups_listbox.pack(fill=tk.Y, expand=True)
        self.groups_listbox.bind("<Double-Button-1>", self.on_group_double_click)
        self.btn_refresh_groups = tk.Button(frame_left, text="刷新群聊列表", command=self.list_groups)
        self.btn_refresh_groups.pack(pady=5)
        self.btn_invite_group = tk.Button(frame_left, text="邀请好友加入群聊", command=self.invite_to_group_dialog)
        self.btn_invite_group.pack(pady=5)
        self.btn_leave_group = tk.Button(frame_left, text="退群", command=self.leave_group_dialog)
        self.btn_leave_group.pack(pady=5)
        self.btn_redistribute_key = tk.Button(frame_left, text="重新分发密钥", command=self.redistribute_group_key)
        self.btn_redistribute_key.pack(pady=5)

        frame_right = tk.Frame(frame_middle)
        frame_right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.txt_chat = scrolledtext.ScrolledText(frame_right, width=60, height=20, state=tk.DISABLED)
        self.txt_chat.pack(fill=tk.BOTH, expand=True)

        frame_bottom = tk.Frame(self.chat_frame)
        frame_bottom.pack(fill=tk.X, padx=5, pady=5)
        self.entry_msg = tk.Entry(frame_bottom)
        self.entry_msg.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.entry_msg.bind("<Return>", self.send_message)
        self.btn_send = tk.Button(frame_bottom, text="发送", command=self.send_message)
        self.btn_send.pack(side=tk.LEFT, padx=5)

        self.append_chat("[系统]", f"用户[{self.username}] 已登录。")
        self.list_friends()
        self.list_groups()

    def on_login_success(self):
        messagebox.showinfo("登录", "登录成功！")
        self.create_chat_interface()

    def load_chat_history(self):
        if not os.path.exists(self.history_file):
            self.chat_history = {}
            return
        try:
            # 如果还没有保存密钥，则提示输入加密密码，否则直接使用内存中的密钥
            if self.chat_history_key is None:
                passphrase = simpledialog.askstring("输入聊天历史加密密码", "请输入您的加密密码：", show='*')
                if not passphrase:
                    messagebox.showerror("错误", "需要加密密码来加载聊天历史")
                    self.chat_history = {}
                    return
                kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'securechatsalt', iterations=100000, backend=default_backend())
                key = kdf.derive(passphrase.encode('utf-8'))
                self.chat_history_key = key
            else:
                key = self.chat_history_key

            with open(self.history_file, 'rb') as f:
                encrypted_data = f.read()
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:-16]
            tag = encrypted_data[-16:]
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize_with_tag(tag)
            self.chat_history = json.loads(plaintext.decode('utf-8'))
        except Exception as e:
            print(f"加载聊天历史失败: {e}")
            messagebox.showerror("错误", "无法加载聊天历史，可能密码错误")
            self.chat_history = {}

    def save_chat_history(self):
        try:
            # 如果还没有保存密钥，则提示输入加密密码，否则直接使用内存中的密钥
            if self.chat_history_key is None:
                passphrase = simpledialog.askstring("设置聊天历史加密密码", "请输入加密密码：", show='*')
                if not passphrase:
                    messagebox.showerror("错误", "需要加密密码来保存聊天历史")
                    return
                kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'securechatsalt', iterations=100000, backend=default_backend())
                key = kdf.derive(passphrase.encode('utf-8'))
                self.chat_history_key = key
            else:
                key = self.chat_history_key

            nonce = get_random_bytes(12)
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(json.dumps(self.chat_history).encode('utf-8')) + encryptor.finalize()
            with open(self.history_file, 'wb') as f:
                f.write(nonce + encrypted_data + encryptor.tag)
        except Exception as e:
            print(f"保存聊天历史失败: {e}")
            messagebox.showerror("错误", "保存聊天历史失败")

    def append_chat(self, sender, content):
        self.txt_chat.config(state=tk.NORMAL)
        self.txt_chat.insert(tk.END, f"{sender}: {content}\n")
        self.txt_chat.yview(tk.END)
        self.txt_chat.config(state=tk.DISABLED)
        if self.current_chat_target and not sender.startswith("[系统]"):
            self.chat_history.setdefault(self.current_chat_target, []).append({"sender": sender, "content": content})
            self.save_chat_history()

    def load_conversation_history(self, conv_id):
        self.txt_chat.config(state=tk.NORMAL)
        self.txt_chat.delete("1.0", tk.END)
        for msg in self.chat_history.get(conv_id, []):
            self.txt_chat.insert(tk.END, f"{msg['sender']}: {msg['content']}\n")
        self.txt_chat.config(state=tk.DISABLED)

    async def async_connect_server(self):
        ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        # 不加载本地证书文件，依赖系统信任存储
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        print(f"尝试连接 {self.server_ip}:{self.server_port}")
        max_retries = 3
        for attempt in range(max_retries):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.server_ip, self.server_port, ssl=ssl_ctx),
                    timeout=30
                )
                self.reader, self.writer = reader, writer
                print("已连接到服务器 (TLS)")
                asyncio.create_task(self.listen_server())
                return
            except Exception as e:
                print(f"连接尝试 {attempt + 1}/{max_retries} 失败: {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2)
                else:
                    raise ConnectionError(f"无法连接到服务器，经过 {max_retries} 次尝试: {e}")

    async def listen_server(self):
        try:
            while True:
                line = await self.reader.readline()
                if not line:
                    if hasattr(self, 'txt_chat'):
                        self.append_chat("[系统]", "与服务器断开连接。")
                    break
                text = line.decode('utf-8', errors='ignore').strip()
                if text:
                    self.handle_server_message(text)
        except Exception as e:
            if hasattr(self, 'txt_chat'):
                self.append_chat("[错误]", f"监听服务器异常: {e}")
        finally:
            if self.writer:
                self.writer.close()
                await self.writer.wait_closed()

    def handle_server_message(self, text):
        try:
            msg = json.loads(text)
        except:
            return
        action = msg.get("action")
        data = msg.get("data", {})

        if action == "register_result":
            self.handle_register_result(data)
        elif action == "login_result":
            self.handle_login_result(data)
        elif action == "reset_password_result":
            self.handle_reset_password_result(data)
        elif action == "check_user_email_result":
            self.handle_check_user_email_result(data)
        elif action == "search_result":
            self.handle_search_result(data)
        elif action == "chat_invite":
            self.handle_chat_invite(data)
        elif action == "chat_request_fail":
            self.handle_chat_request_fail(data)
        elif action == "chat_accepted":
            self.handle_chat_accepted(data)
        elif action == "chat_declined":
            self.handle_chat_declined(data)
        elif action == "dh_exchange":
            self.handle_dh_exchange_msg(data)
        elif action == "receive_message":
            self.handle_receive_message(data)
        elif action == "add_friend_result":
            self.handle_add_friend_result(data)
        elif action == "list_friends_result":
            self.handle_list_friends_result(data)
        elif action == "create_group_result":
            self.handle_create_group_result(data)
        elif action == "group_invite":
            self.handle_group_invite(data)
        elif action == "receive_group_message":
            self.handle_receive_group_message(data)
        elif action == "list_groups_result":
            self.handle_list_groups_result(data)
        elif action == "group_key_distribute":
            self.handle_group_key_distribute(data)
        elif action == "group_members_result":
            self.handle_group_members_result(data)
        elif action == "delete_friend_result":
            self.handle_delete_friend_result(data)
        elif action == "leave_group_result":
            self.handle_leave_group_result(data)
        elif action == "invite_to_group_result":
            self.handle_invite_to_group_result(data)

    def handle_register_result(self, data):
        if data.get("ok"):
            messagebox.showinfo("注册", "注册成功，请登录！")
            self.show_login_form()
        else:
            messagebox.showerror("注册失败", f"注册失败: {data.get('error', '未知错误')}")

    def handle_login_result(self, data):
        if data.get("ok"):
            self.on_login_success()
        else:
            messagebox.showerror("登录失败", data.get("error", "用户名或密码错误"))

    def handle_reset_password_result(self, data):
        if data.get("ok"):
            messagebox.showinfo("重置密码", "密码重置成功，请使用新密码登录！")
            self.show_login_form()
        else:
            messagebox.showerror("重置密码失败", f"密码重置失败: {data.get('error', '未知错误')}")

    def handle_check_user_email_result(self, data):
        print(f"调试：服务器返回数据 - {data}")
        if data.get("ok"):
            self.email_sent = True
            messagebox.showinfo("验证码", "验证码已发送至您的邮箱，请检查收件箱！")
            print("调试：验证码发送成功")
        else:
            self.email_sent = False
            error_msg = data.get('error', '未知错误')
            messagebox.showerror("验证失败", f"验证失败: {error_msg}")
            print(f"调试：验证码发送失败 - {error_msg}")

    def handle_search_result(self, data):
        results = data.get("results", [])
        if not results:
            messagebox.showinfo("搜索结果", "没有匹配的用户")
            return
        lines = [f"{r['username']} ({'在线' if r['online'] else '离线'})" for r in results]
        messagebox.showinfo("搜索结果", "\n".join(lines))

    def handle_chat_invite(self, data):
        from_user = data.get("from_user")
        if not from_user or from_user == self.username:
            return
        accept = messagebox.askyesno("聊天请求", f"用户[{from_user}]想和你聊天，是否接受？")
        asyncio.run_coroutine_threadsafe(
            self.async_send({"action": "chat_response", "data": {"from_user": from_user, "accept": accept}}),
            self.loop
        )
        if accept:
            self.start_dh_exchange(from_user)
            self.current_chat_target = from_user
            self.load_conversation_history(self.current_chat_target)

    def handle_chat_request_fail(self, data):
        messagebox.showerror("请求失败", data.get("error", "聊天请求失败"))

    def handle_chat_accepted(self, data):
        from_user = data.get("from_user")
        if from_user and from_user != self.username:
            self.append_chat("[系统]", f"用户[{from_user}]接受聊天请求，开始密钥交换...")
            self.start_dh_exchange(from_user)
            self.current_chat_target = from_user
            self.load_conversation_history(self.current_chat_target)

    def handle_chat_declined(self, data):
        from_user = data.get("from_user")
        if from_user:
            messagebox.showinfo("对方拒绝", f"用户[{from_user}]拒绝了聊天")

    def handle_dh_exchange_msg(self, data):
        from_user = data.get("from_user")
        pub_key_hex = data.get("public_key")
        if from_user and pub_key_hex and from_user != self.username:
            self.finish_dh_exchange(from_user, pub_key_hex)

    def handle_receive_message(self, data):
        from_user = data.get("from_user")
        ciphertext_b64 = data.get("ciphertext")
        nonce_b64 = data.get("nonce")
        tag_b64 = data.get("tag")
        self.decrypt_and_show(from_user, ciphertext_b64, nonce_b64, tag_b64)

    def handle_add_friend_result(self, data):
        if data.get("ok"):
            messagebox.showinfo("添加好友", "添加成功！")
            self.list_friends()
        else:
            messagebox.showerror("添加好友失败", data.get("error", "无法添加好友"))

    def handle_list_friends_result(self, data):
        friends = data.get("friends", [])
        self.friends_listbox.delete(0, tk.END)
        for f in friends:
            uname = f["username"]
            status_str = "在线" if f["online"] else "离线"
            self.friends_listbox.insert(tk.END, f"{uname} ({status_str})")
        self.btn_delete_friend.config(state=tk.NORMAL if friends else tk.DISABLED)

    def handle_create_group_result(self, data):
        if data.get("ok"):
            group_id = data.get("group_id")
            messagebox.showinfo("创建群聊", "群聊创建成功！")
            self.group_creators[str(group_id)] = self.username
            self.group_keys[str(group_id)] = get_random_bytes(32)
            self.append_chat("[系统]", f"群聊[{group_id}]密钥已生成")
            self.distribute_group_key(group_id)
            self.list_groups()
        else:
            messagebox.showerror("创建群聊失败", data.get("error", "创建失败"))

    def handle_group_invite(self, data):
        group_id = data.get("group_id")
        group_name = data.get("group_name", "")
        from_user = data.get("from_user")
        messagebox.showinfo("群聊邀请", f"用户[{from_user}]邀请您加入群聊[{group_name}]")
        self.group_creators[str(group_id)] = from_user
        self.list_groups()

    def handle_receive_group_message(self, data):
        group_id = data.get("group_id")
        from_user = data.get("from_user")
        ciphertext_b64 = data.get("ciphertext")
        nonce_b64 = data.get("nonce")
        tag_b64 = data.get("tag")
        key = self.group_keys.get(str(group_id))
        if not key:
            self.append_chat("[系统]", f"群聊[{group_id}]缺少密钥，请等待创建者分发")
            return
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            nonce = base64.b64decode(nonce_b64)
            tag = base64.b64decode(tag_b64)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            cipher.update(b"")
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            message = plaintext.decode('utf-8')
            self.append_chat(f"群聊[{group_id}] {from_user}", message)
        except Exception as e:
            self.append_chat("[错误]", f"解密群聊[{group_id}]消息失败: {e}")

    def handle_list_groups_result(self, data):
        groups = data.get("groups", [])
        self.groups_listbox.delete(0, tk.END)
        for g in groups:
            group_id = g["group_id"]
            group_name = g["group_name"]
            creator = g.get("creator")
            self.groups_listbox.insert(tk.END, f"{group_name} (ID:{group_id})")
            if creator:
                self.group_creators[str(group_id)] = creator
        self.btn_invite_group.config(state=tk.NORMAL if groups else tk.DISABLED)
        self.btn_leave_group.config(state=tk.NORMAL if groups else tk.DISABLED)

    def handle_group_key_distribute(self, data):
        group_id = data.get("group_id")
        encrypted_key_b64 = data.get("encrypted_key")
        if group_id and encrypted_key_b64:
            try:
                encrypted_key = base64.b64decode(encrypted_key_b64)
                cipher = PKCS1_OAEP.new(self.private_key)
                key = cipher.decrypt(encrypted_key)
                self.group_keys[str(group_id)] = key
                self.append_chat("[系统]", f"已接收并解密群聊[{group_id}]的密钥")
            except Exception as e:
                self.append_chat("[错误]", f"解密群聊[{group_id}]密钥失败: {e}")

    def handle_group_members_result(self, data):
        group_id = data.get("group_id")
        members = data.get("members", {})
        key = self.group_keys.get(str(group_id))
        if not key or not members:
            self.append_chat("[系统]", f"群聊[{group_id}]分发密钥失败：缺少密钥或成员信息")
            return
        encrypted_keys = {}
        for member, pubkey_pem in members.items():
            if member == self.username:
                continue
            pubkey = RSA.import_key(pubkey_pem)
            cipher = PKCS1_OAEP.new(pubkey)
            encrypted_key = cipher.encrypt(key)
            encrypted_keys[member] = base64.b64encode(encrypted_key).decode('utf-8')
        asyncio.run_coroutine_threadsafe(
            self.async_send({
                "action": "group_key_distribute",
                "data": {"group_id": group_id, "encrypted_keys": encrypted_keys}
            }),
            self.loop
        )
        self.append_chat("[系统]", f"群聊[{group_id}]密钥已加密分发")

    def handle_delete_friend_result(self, data):
        if data.get("ok"):
            messagebox.showinfo("删除好友", "好友删除成功！")
            if self.current_chat_target and self.current_chat_target in self.chat_history:
                del self.chat_history[self.current_chat_target]
                self.save_chat_history()
            self.list_friends()
        else:
            messagebox.showerror("删除好友失败", data.get("error", "删除好友失败"))

    def handle_leave_group_result(self, data):
        if data.get("ok"):
            messagebox.showinfo("退群", "退群成功！")
            conv_id = self.current_chat_target
            if conv_id and conv_id in self.chat_history:
                del self.chat_history[conv_id]
                self.save_chat_history()
            self.list_groups()
        else:
            messagebox.showerror("退群失败", data.get("error", "退群失败"))

    def handle_invite_to_group_result(self, data):
        if data.get("ok"):
            messagebox.showinfo("邀请群聊", "邀请发送成功！")
            self.list_groups()
        else:
            messagebox.showerror("邀请失败", data.get("error", "邀请失败"))

    def search_dialog(self):
        kw = simpledialog.askstring("搜索用户", "输入关键字（字母数字）：")
        if kw and re.match(r'^[a-zA-Z0-9_]+$', kw):
            asyncio.run_coroutine_threadsafe(
                self.async_send({"action": "search", "data": {"keyword": kw}}),
                self.loop
            )
        else:
            messagebox.showwarning("警告", "无效的关键字格式")

    def add_friend_dialog(self):
        friend_name = simpledialog.askstring("添加好友", "请输入对方用户名（3-20位字母数字）：")
        if friend_name and re.match(r'^[a-zA-Z0-9_]{3,20}$', friend_name):
            asyncio.run_coroutine_threadsafe(
                self.async_send({"action": "add_friend", "data": {"friend_name": friend_name}}),
                self.loop
            )
        else:
            messagebox.showwarning("警告", "无效的用户名格式")

    def list_friends(self):
        asyncio.run_coroutine_threadsafe(
            self.async_send({"action": "list_friends", "data": {}}),
            self.loop
        )

    def on_friend_double_click(self, event):
        selection = self.friends_listbox.curselection()
        if not selection:
            return
        friend_line = self.friends_listbox.get(selection[0])
        friend_name = friend_line.split(' (')[0]
        if friend_name:
            self.current_chat_target = friend_name
            asyncio.run_coroutine_threadsafe(
                self.async_send({"action": "chat_request", "data": {"target": friend_name}}),
                self.loop
            )
            self.append_chat("[系统]", f"向[{friend_name}]发起聊天请求...")
            self.load_conversation_history(self.current_chat_target)

    def create_group_dialog(self):
        group_name = simpledialog.askstring("创建群聊", "请输入群聊名字（字母数字）：")
        if not group_name or not re.match(r'^[a-zA-Z0-9_]+$', group_name):
            messagebox.showwarning("警告", "无效的群聊名字")
            return
        friends = [self.friends_listbox.get(i).split(' (')[0] for i in range(self.friends_listbox.size())]
        if not friends:
            messagebox.showinfo("提示", "您还没有好友")
            return
        selected_friends = self.select_friends(friends)
        if not selected_friends:
            return
        members = selected_friends + [self.username]
        asyncio.run_coroutine_threadsafe(
            self.async_send({"action": "create_group", "data": {"group_name": group_name, "members": members}}),
            self.loop
        )

    def select_friends(self, friends):
        selected_friends = simpledialog.askstring("选择成员", "请选择好友（用逗号分隔）：", initialvalue=",".join(friends))
        if not selected_friends:
            return []
        return [f.strip() for f in selected_friends.split(',') if f.strip() and re.match(r'^[a-zA-Z0-9_]{3,20}$', f.strip())]

    def list_groups(self):
        asyncio.run_coroutine_threadsafe(
            self.async_send({"action": "list_groups", "data": {}}),
            self.loop
        )

    def on_group_double_click(self, event):
        selection = self.groups_listbox.curselection()
        if not selection:
            return
        group_line = self.groups_listbox.get(selection[0])
        group_id = int(group_line.split("ID:")[1].strip(")"))
        self.current_chat_target = f"group_{group_id}"
        if str(group_id) not in self.group_keys and self.group_creators.get(str(group_id)) != self.username:
            self.append_chat("[系统]", f"群聊[{group_id}]尚未收到密钥，请等待创建者分发")
        self.append_chat("[系统]", f"进入群聊[{group_id}]")
        self.load_conversation_history(self.current_chat_target)
        if self.group_creators.get(str(group_id)) == self.username:
            self.btn_redistribute_key.config(state=tk.NORMAL)
        else:
            self.btn_redistribute_key.config(state=tk.DISABLED)

    def invite_to_group_dialog(self):
        if not self.current_chat_target or not self.current_chat_target.startswith("group_"):
            messagebox.showwarning("警告", "请先选择一个群聊！")
            return
        friends = [self.friends_listbox.get(i).split(' (')[0] for i in range(self.friends_listbox.size())]
        if not friends:
            messagebox.showinfo("提示", "您没有好友")
            return
        selected_friend = self.select_friends(friends)
        if not selected_friend:
            return
        group_id = int(self.current_chat_target.split("_")[1])
        asyncio.run_coroutine_threadsafe(
            self.async_send({"action": "invite_to_group", "data": {"group_id": group_id, "friend_name": selected_friend[0]}}),
            self.loop
        )

    def delete_friend_dialog(self):
        selection = self.friends_listbox.curselection()
        if not selection:
            messagebox.showwarning("警告", "请选择要删除的好友")
            return
        friend_line = self.friends_listbox.get(selection[0])
        friend_name = friend_line.split(' (')[0]
        if messagebox.askyesno("删除好友", f"确定删除好友[{friend_name}]并清除与其的聊天记录吗？"):
            asyncio.run_coroutine_threadsafe(
                self.async_send({"action": "delete_friend", "data": {"friend_name": friend_name}}),
                self.loop
            )

    def leave_group_dialog(self):
        if not self.current_chat_target or not self.current_chat_target.startswith("group_"):
            messagebox.showwarning("警告", "请先选择一个群聊！")
            return
        group_id = int(self.current_chat_target.split("_")[1])
        if messagebox.askyesno("退群", f"确定退出群聊[{group_id}]吗？"):
            asyncio.run_coroutine_threadsafe(
                self.async_send({"action": "leave_group", "data": {"group_id": group_id}}),
                self.loop
            )

    def distribute_group_key(self, group_id):
        key = self.group_keys.get(str(group_id))
        if not key:
            self.append_chat("[系统]", f"群聊[{group_id}]密钥未生成，无法分发")
            return
        asyncio.run_coroutine_threadsafe(
            self.async_send({"action": "get_group_members", "data": {"group_id": group_id}}),
            self.loop
        )

    def redistribute_group_key(self):
        if not self.current_chat_target or not self.current_chat_target.startswith("group_"):
            messagebox.showwarning("警告", "请先选择一个群聊！")
            return
        group_id = int(self.current_chat_target.split("_")[1])
        if self.group_creators.get(str(group_id)) != self.username:
            messagebox.showwarning("警告", "只有群聊创建者可以重新分发密钥！")
            return
        new_key = get_random_bytes(32)
        self.group_keys[str(group_id)] = new_key
        self.append_chat("[系统]", f"群聊[{group_id}]已生成新密钥")
        self.distribute_group_key(group_id)

    def start_dh_exchange(self, partner):
        if partner == self.username:
            return
        a = getRandomRange(2, DH_P - 2)
        A = pow(DH_G, a, DH_P)
        A_hex = format(A, 'x')
        self.dh_states[partner] = a
        asyncio.run_coroutine_threadsafe(
            self.async_send({"action": "dh_exchange", "data": {"target": partner, "public_key": A_hex}}),
            self.loop
        )
        self.append_chat("[系统]", f"正在与[{partner}]进行密钥交换...")

    def finish_dh_exchange(self, from_user, pub_key_hex):
        B = int(pub_key_hex, 16)
        a = self.dh_states.get(from_user)
        if a is None:
            return
        shared_secret = pow(B, a, DH_P)
        key_bytes = SHA256.new(str(shared_secret).encode('utf-8')).digest()
        self.shared_keys[from_user] = key_bytes
        self.append_chat("[系统]", f"与[{from_user}]的DH密钥交换完成，可以安全聊天了。")
        del self.dh_states[from_user]

    def encrypt_and_send(self, target, plaintext):
        key = self.shared_keys.get(target)
        if not key:
            self.append_chat("[系统]", f"尚未与[{target}]完成密钥交换！")
            if target != self.username:
                self.start_dh_exchange(target)
            return
        cipher = AES.new(key, AES.MODE_GCM)
        cipher.update(b"")
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        nonce_b64 = base64.b64encode(cipher.nonce).decode('utf-8')
        tag_b64 = base64.b64encode(tag).decode('utf-8')
        asyncio.run_coroutine_threadsafe(
            self.async_send({
                "action": "send_message",
                "data": {"target": target, "ciphertext": ciphertext_b64, "nonce": nonce_b64, "tag": tag_b64}
            }),
            self.loop
        )

    def decrypt_and_show(self, from_user, ciphertext_b64, nonce_b64, tag_b64):
        key = self.shared_keys.get(from_user)
        if not key:
            self.append_chat("[系统]", f"收到[{from_user}]消息但尚未完成密钥交换！")
            if from_user != self.username:
                self.start_dh_exchange(from_user)
            return
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            nonce = base64.b64decode(nonce_b64)
            tag = base64.b64decode(tag_b64)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            cipher.update(b"")
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            message = plaintext.decode('utf-8')
            self.append_chat(from_user, message)
        except Exception as e:
            self.append_chat("[错误]", f"解密[{from_user}]消息失败: {e}")

    def send_message(self, event=None):
        msg = self.entry_msg.get().strip()
        if not msg or len(msg) > 1000:
            messagebox.showwarning("警告", "消息为空或过长（最大1000字符）")
            return
        self.entry_msg.delete(0, tk.END)
        if not self.current_chat_target:
            self.append_chat("[系统]", "请先选择聊天对象或群聊。")
            return
        if self.current_chat_target.startswith("group_"):
            group_id = int(self.current_chat_target.split("_")[1])
            key = self.group_keys.get(str(group_id))
            if not key:
                self.append_chat("[系统]", f"群聊[{group_id}]缺少密钥，无法发送")
                return
            cipher = AES.new(key, AES.MODE_GCM)
            cipher.update(b"")
            ciphertext, tag = cipher.encrypt_and_digest(msg.encode('utf-8'))
            ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
            nonce_b64 = base64.b64encode(cipher.nonce).decode('utf-8')
            tag_b64 = base64.b64encode(tag).decode('utf-8')
            asyncio.run_coroutine_threadsafe(
                self.async_send({
                    "action": "send_group_message",
                    "data": {"group_id": group_id, "ciphertext": ciphertext_b64, "nonce": nonce_b64, "tag": tag_b64}
                }),
                self.loop
            )
            self.append_chat(f"我 -> 群聊[{group_id}]", msg)
        else:
            self.append_chat(f"我 -> {self.current_chat_target}", msg)
            self.encrypt_and_send(self.current_chat_target, msg)

    async def async_send(self, obj):
        if not self.writer:
            messagebox.showerror("错误", "未连接到服务器！")
            print("调试：未连接到服务器")
            return
        data = (json.dumps(obj) + "\n").encode('utf-8')
        print(f"调试：发送数据 - {obj}")
        await self._async_write(data)

    async def _async_write(self, data):
        try:
            self.writer.write(data)
            await self.writer.drain()
            print("调试：数据已发送")
        except Exception as e:
            print(f"调试：发送数据失败 - {e}")

def run_asyncio(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()

def main():
    root = tk.Tk()
    app = E2EEChatClient(root)
    
    asyncio_thread = threading.Thread(target=run_asyncio, args=(app.loop,), daemon=True)
    asyncio_thread.start()
    
    root.mainloop()

if __name__ == "__main__":
    main()
