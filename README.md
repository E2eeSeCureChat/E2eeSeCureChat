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
## server machine Requirements

- Python 3.7+
- Required libraries: `tkinter`, `asyncio`, `json`, `ssl`, `passlib`, `cryptography`

You can install the necessary dependencies using `pip`:

```bash
pip install passlib cryptography
```
or you can use `requirments.txt`

```bash
pip install -r requirements-server.txt
```

## 服务器安装库要求

- python 3.7+
- 需求的库: `tkinter`, `asyncio`, `json`, `ssl`, `passlib`, `cryptography`

你可以使用`pip`安装必须的库:

```bash
pip install passlib cryptography
```
或者你可以使用`requirments-server.txt`

```bash
pip install -r requirements-server.txt
```

## client machine Requirements

- Python 3.7+
- Required libraries: `tkinter`, `asyncio`, `json`, `ssl`, `pycryptodome`, `cryptography`

You can install the necessary dependencies using `pip`:

```bash
pip install pycryptodome cryptography
```
or you can use `requirments.txt`

```bash
pip install -r requirements-client.txt
```
## 客户端安装库要求

- python 3.7+
- 需求的库: `tkinter`, `asyncio`, `json`, `ssl`, `pycryptodome`, `cryptography`

你可以使用`pip`安装必须的库:

```bash
pip install pycryptodome cryptography
```
或者你可以使用`requirment.txt`

```bash
pip install -r requirements.txt
```

---
## Usage
- Run the Python script to start the application.
- Register a new account or log in with an existing one.
- Once logged in, you can start secure one-on-one or group chats.
- Use the various buttons to add friends, create groups, and manage your chat history.
- On the server machine, run the server script:
   ```bash
   python e2eechat-securechat-server.py
   ```
- On the client machine, run the client script:
    ```bash
   python e2eechat-securechat-client.py
   ``` 
## 使用方法
- 运行 Python 脚本以启动应用程序。
- 注册新帐户或使用现有帐户登录。
- 登录后，您可以开始一对一的安全聊天或群聊。
- 使用各个按钮来添加好友、创建群组和管理聊天记录。
- 在服务器上运行以下命令启动服务端：
   ```bash
   python e2eechat-securechat-server.py
   ```
-在客户端上运行以下命令启动聊天客户端：
   ```bash
   python e2eechat-securechat-client.py
   ```
---
## Security and Privacy
- End-to-End Encryption: All communication is encrypted on the client-side. Even the server cannot read your messages.
- Private Key Storage: Private keys are stored securely and are used to encrypt/decrypt messages.
- Chat History Encryption: Chat history is encrypted using AES with a password key.

## 安全与隐私
- 端到端加密：所有通信都在客户端加密，即使服务器也无法读取您的消息。
- 私钥存储：私钥被安全存储，用于加密/解密消息。
- 聊天记录加密：聊天记录使用 AES 加密，并通过密码密钥进行保护。
