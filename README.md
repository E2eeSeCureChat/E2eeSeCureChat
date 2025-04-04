# SeCureChat - End-to-End Encrypted Chat Application

## Overview

**SeCureChat** is a secure chat application that ensures end-to-end encryption for user communications. It provides a variety of features such as user registration, login, password reset, adding friends, creating and managing group chats, as well as secure messaging with encryption protocols like RSA and AES. 

The application supports Diffie-Hellman key exchange for secure key distribution, uses RSA for public-key encryption, and AES for symmetric encryption of messages.

---

## 功能简介

**SeCureChat** 是一个保证端到端加密的安全聊天应用程序。它提供了多种功能，包括用户注册、登录、密码重置、添加好友、创建和管理群聊，以及使用RSA和AES等加密协议进行安全消息传递。

该应用程序支持Diffie-Hellman密钥交换来确保密钥的安全分发，使用RSA进行公钥加密，使用AES进行消息的对称加密。

---

## Features

### User Authentication
- **Registration**: Create a new account by providing a username, password, and email.
- **Login**: Secure login using username and password.
- **Password Reset**: Recover or reset your password by verifying your email.

### Secure Messaging
- **End-to-End Encryption**: All messages are encrypted using AES in GCM mode.
- **Diffie-Hellman Key Exchange**: Secure key exchange between users using DH for establishing shared secrets.
- **Group Chat**: Create and manage group chats with encryption for group messages.

### Friend Management
- **Add Friends**: Search for users and send friend requests.
- **Delete Friends**: Remove users from your friend list.

### Group Management
- **Create Group**: Start a new group chat with friends.
- **Invite Friends to Group**: Invite friends to join your group chat.
- **Leave Group**: Leave any group chat.

### Chat History
- **Save Chat History**: Your chat history is encrypted and saved locally.
- **Load Chat History**: Retrieve previous conversations securely after re-login.

---

## 功能

### 用户认证
- **注册**：通过提供用户名、密码和邮箱创建新帐户。
- **登录**：使用用户名和密码进行安全登录。
- **重置密码**：通过验证邮箱恢复或重置密码。

### 安全消息传递
- **端到端加密**：所有消息使用AES-GCM模式加密。
- **Diffie-Hellman密钥交换**：使用Diffie-Hellman算法在用户之间安全交换密钥以建立共享密钥。
- **群聊**：创建和管理群聊，群消息加密传输。

### 好友管理
- **添加好友**：搜索用户并发送好友请求。
- **删除好友**：从好友列表中移除用户。

### 群组管理
- **创建群组**：与好友一起创建新的群聊。
- **邀请好友加入群聊**：邀请好友加入群聊。
- **退出群聊**：退出任何群聊。

### 聊天记录
- **保存聊天记录**：聊天记录加密后保存在本地。
- **加载聊天记录**：重新登录后安全地加载之前的聊天记录。

---

## Requirements

- Python 3.7+
- Required libraries: `tkinter`, `asyncio`, `json`, `ssl`, `pycryptodome`, `cryptography`

You can install the necessary dependencies using `pip`:

```bash
pip install pycryptodome cryptography



**解释**：
- ```bash 表示代码块的语言类型是 Bash，这样在显示时可以进行语法高亮。
- 使用反引号包裹代码块，这样 Markdown 渲染时会将代码格式化为块状展示。

### 示例：
```bash
#!/bin/bash

# 打印“Hello, World!”
echo "Hello, World!"

# 列出当前目录下的所有文件
ls -l
