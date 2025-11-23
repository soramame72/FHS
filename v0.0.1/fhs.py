#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import hashlib
import json
import os
import sys
import re
import time
from pathlib import Path
from datetime import datetime
import socket
import struct

# 暗号化関連
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Protocol.KDF import PBKDF2
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# ========== 暗号化ユーティリティ ==========
class SimpleCrypto:
    @staticmethod
    def xor_encrypt(data: bytes, password: str) -> bytes:
        key = hashlib.sha256(password.encode()).digest()
        result = bytearray()
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % len(key)])
        return bytes(result)
    
    @staticmethod
    def xor_decrypt(data: bytes, password: str) -> bytes:
        return SimpleCrypto.xor_encrypt(data, password)


if CRYPTO_AVAILABLE:
    class Crypto:
        @staticmethod
        def derive_key(password: str, salt: bytes) -> bytes:
            return PBKDF2(password, salt, dkLen=32, count=100000)
        
        @staticmethod
        def encrypt(data: bytes, password: str) -> bytes:
            salt = get_random_bytes(16)
            key = Crypto.derive_key(password, salt)
            cipher = AES.new(key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            return salt + cipher.nonce + tag + ciphertext
        
        @staticmethod
        def decrypt(data: bytes, password: str) -> bytes:
            salt = data[:16]
            nonce = data[16:32]
            tag = data[32:48]
            ciphertext = data[48:]
            key = Crypto.derive_key(password, salt)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)
else:
    Crypto = SimpleCrypto


# ========== P2Pサーバー ==========
class P2PServer:
    def __init__(self, folder, password, port, use_password, use_ipban, log_callback):
        self.folder = Path(folder)
        self.password = password
        self.password_hash = hashlib.sha256(password.encode()).hexdigest() if password else None
        self.port = port
        self.use_password = use_password
        self.use_ipban = use_ipban
        self.log_callback = log_callback
        self.server_socket = None
        self.running = False
        self.blocked_ips = set()
        self.failed_attempts = {}
    
    def start(self):
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(("0.0.0.0", self.port))
        self.server_socket.listen(5)
        self.log_callback(f"[起動] P2Pサーバー起動: 0.0.0.0:{self.port}")
        
        if not self.use_password:
            self.log_callback("[情報] パスワード認証: 無効")
        if not self.use_ipban:
            self.log_callback("[情報] IPブロック: 無効")
        
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                try:
                    client_socket, client_address = self.server_socket.accept()
                    threading.Thread(target=self.handle_client, args=(client_socket, client_address), daemon=True).start()
                except socket.timeout:
                    continue
            except Exception as e:
                if self.running:
                    self.log_callback(f"[エラー] {str(e)}")
    
    def handle_client(self, client_socket, client_address):
        client_ip = client_address[0]
        
        try:
            # IPブロックチェック
            if self.use_ipban and client_ip in self.blocked_ips:
                self.send_response(client_socket, {"status": "error", "message": "IP Blocked"})
                self.log_callback(f"[拒否] ブロック済みIP: {client_ip}")
                client_socket.close()
                return
            
            # リクエスト受信
            request_data = self.receive_data(client_socket)
            if not request_data:
                client_socket.close()
                return
            
            request = json.loads(request_data.decode('utf-8'))
            command = request.get("command")
            
            # パスワード認証
            if self.use_password:
                auth = request.get("auth", "")
                if auth != self.password_hash:
                    if self.use_ipban:
                        self.failed_attempts[client_ip] = self.failed_attempts.get(client_ip, 0) + 1
                        if self.failed_attempts[client_ip] >= 3:
                            self.blocked_ips.add(client_ip)
                            self.log_callback(f"[警告] IP自動ブロック: {client_ip}")
                    
                    self.send_response(client_socket, {"status": "error", "message": "Unauthorized"})
                    self.log_callback(f"[拒否] 認証失敗: {client_ip}")
                    client_socket.close()
                    return
                
                if self.use_ipban:
                    self.failed_attempts[client_ip] = 0
            
            # コマンド処理
            if command == "list":
                self.handle_list(client_socket, client_ip)
            elif command == "download":
                filename = request.get("filename")
                self.handle_download(client_socket, client_ip, filename)
            else:
                self.send_response(client_socket, {"status": "error", "message": "Unknown command"})
            
        except Exception as e:
            self.log_callback(f"[エラー] {client_ip}: {type(e).__name__} - {str(e)}")
        finally:
            client_socket.close()
    
    def handle_list(self, client_socket, client_ip):
        files = []
        for item in self.folder.rglob("*"):
            if item.is_file():
                rel_path = item.relative_to(self.folder)
                files.append({
                    "name": str(rel_path).replace("\\", "/"),
                    "size": item.stat().st_size
                })
        
        self.send_response(client_socket, {"status": "success", "files": files})
        self.log_callback(f"[接続] ファイル一覧送信: {client_ip} ({len(files)}ファイル)")
    
    def handle_download(self, client_socket, client_ip, filename):
        try:
            file_path = (self.folder / filename).resolve()
            
            # セキュリティチェック
            if not str(file_path).startswith(str(self.folder.resolve())):
                self.send_response(client_socket, {"status": "error", "message": "Access denied"})
                self.log_callback(f"[エラー] 不正アクセス試行: {filename}")
                return
            
            if not file_path.exists():
                self.send_response(client_socket, {"status": "error", "message": "File not found"})
                self.log_callback(f"[エラー] ファイル不明: {filename}")
                return
            
            with open(file_path, "rb") as f:
                data = f.read()
            
            # 暗号化（パスワードありの場合のみ）
            if self.use_password and self.password:
                if CRYPTO_AVAILABLE:
                    data = Crypto.encrypt(data, self.password_hash)
                else:
                    data = Crypto.xor_encrypt(data, self.password_hash)
            
            self.send_response(client_socket, {"status": "success", "size": len(data)})
            self.send_data(client_socket, data)
            
            size_mb = len(data) / (1024 * 1024)
            self.log_callback(f"[送信] {filename} -> {client_ip} ({size_mb:.2f}MB)")
            
        except Exception as e:
            self.send_response(client_socket, {"status": "error", "message": str(e)})
            self.log_callback(f"[エラー] {filename}: {type(e).__name__} - {str(e)}")
    
    def send_response(self, client_socket, response):
        data = json.dumps(response).encode('utf-8')
        self.send_data(client_socket, data)
    
    def send_data(self, client_socket, data):
        # データ長を送信
        length = len(data)
        client_socket.sendall(struct.pack('!I', length))
        # データ本体を送信
        client_socket.sendall(data)
    
    def receive_data(self, client_socket):
        # データ長を受信
        length_data = client_socket.recv(4)
        if not length_data:
            return None
        length = struct.unpack('!I', length_data)[0]
        
        # データ本体を受信
        data = b''
        while len(data) < length:
            chunk = client_socket.recv(min(length - len(data), 8192))
            if not chunk:
                return None
            data += chunk
        return data
    
    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()


# ========== P2Pクライアント ==========
class P2PClient:
    def __init__(self, host, port, password, use_password):
        self.host = host
        self.port = port
        self.password = password
        self.password_hash = hashlib.sha256(password.encode()).hexdigest() if password else None
        self.use_password = use_password
    
    def connect_and_send(self, request):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(30)
        
        try:
            client_socket.connect((self.host, self.port))
            
            # 認証情報を追加
            if self.use_password:
                request["auth"] = self.password_hash
            
            # リクエスト送信
            self.send_data(client_socket, json.dumps(request).encode('utf-8'))
            
            # レスポンス受信
            response_data = self.receive_data(client_socket)
            response = json.loads(response_data.decode('utf-8'))
            
            return client_socket, response
        except Exception as e:
            client_socket.close()
            raise e
    
    def get_file_list(self):
        request = {"command": "list"}
        client_socket, response = self.connect_and_send(request)
        client_socket.close()
        
        if response.get("status") == "success":
            return response.get("files", [])
        else:
            raise Exception(response.get("message", "Unknown error"))
    
    def download_file(self, filename):
        request = {"command": "download", "filename": filename}
        client_socket, response = self.connect_and_send(request)
        
        try:
            if response.get("status") == "success":
                # ファイルデータ受信
                data = self.receive_data(client_socket)
                
                # 復号化（パスワードありの場合のみ）
                if self.use_password and self.password:
                    if CRYPTO_AVAILABLE:
                        data = Crypto.decrypt(data, self.password_hash)
                    else:
                        data = Crypto.xor_decrypt(data, self.password_hash)
                
                return data
            else:
                raise Exception(response.get("message", "Unknown error"))
        finally:
            client_socket.close()
    
    def send_data(self, client_socket, data):
        length = len(data)
        client_socket.sendall(struct.pack('!I', length))
        client_socket.sendall(data)
    
    def receive_data(self, client_socket):
        length_data = client_socket.recv(4)
        if not length_data:
            return None
        length = struct.unpack('!I', length_data)[0]
        
        data = b''
        while len(data) < length:
            chunk = client_socket.recv(min(length - len(data), 8192))
            if not chunk:
                return None
            data += chunk
        return data


# ========== Windows 98風ボタン ==========
class Win98Button(tk.Button):
    def __init__(self, parent, **kwargs):
        default_config = {
            'relief': tk.RAISED,
            'bd': 2,
            'bg': "#C0C0C0",
            'fg': "#000000",
            'activebackground': "#E0E0E0",
            'activeforeground': "#000000",
            'font': ("MS UI Gothic", 9, "bold"),
            'cursor': "hand2",
            'padx': 15,
            'pady': 8
        }
        
        for key, value in kwargs.items():
            default_config[key] = value
        
        super().__init__(parent, **default_config)
        
        self.default_bg = default_config['bg']
        
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.bind("<ButtonPress-1>", self.on_press)
        self.bind("<ButtonRelease-1>", self.on_release)
    
    def on_enter(self, e):
        if self['state'] != 'disabled':
            current_bg = self['bg']
            if current_bg in ["#00AA00", "#4CAF50"]:
                self['bg'] = "#00CC00"
            elif current_bg in ["#CC0000", "#F44336"]:
                self['bg'] = "#FF0000"
            elif current_bg in ["#000080", "#2196F3"]:
                self['bg'] = "#0000AA"
            elif current_bg == "#FF9800":
                self['bg'] = "#FFB300"
            else:
                self['bg'] = "#D0D0D0"
    
    def on_leave(self, e):
        if self['state'] != 'disabled':
            self['bg'] = self.default_bg
    
    def on_press(self, e):
        if self['state'] != 'disabled':
            self['relief'] = tk.SUNKEN
    
    def on_release(self, e):
        if self['state'] != 'disabled':
            self['relief'] = tk.RAISED


# ========== メインアプリケーション ==========
class FHSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("FHS")
        self.root.geometry("850x700")
        self.root.resizable(True, True)
        
        self.bg_color = "#E8E8E8"
        self.panel_color = "#F5F5F5"
        self.text_color = "#000000"
        self.title_bg = "#003366"
        self.title_fg = "#FFFFFF"
        
        self.root.configure(bg=self.bg_color)
        
        self.server = None
        self.server_thread = None
        
        self.create_widgets()
        
        if not CRYPTO_AVAILABLE:
            messagebox.showwarning(
                "警告", 
                "pycryptodomがインストールされていません。\n"
                "簡易暗号化モードで動作します。\n\n"
                "推奨: pip install pycryptodome"
            )
    
    def create_widgets(self):
        # タイトルフレーム
        title_frame = tk.Frame(self.root, bg=self.title_bg, relief=tk.FLAT, bd=0)
        title_frame.pack(fill=tk.X, padx=0, pady=0)
        
        title_label = tk.Label(
            title_frame,
            text=" FHS ",
            font=("MS UI Gothic", 14, "bold"),
            bg=self.title_bg,
            fg=self.title_fg,
            pady=12
        )
        title_label.pack()
        
        # メニューバー
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        info_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="情報", menu=info_menu)
        info_menu.add_command(label="FHSについて", command=self.show_about)
        
        # ノートブック
        style = ttk.Style()
        style.theme_use('default')
        
        style.configure('TNotebook', background=self.bg_color, borderwidth=0)
        style.configure('TNotebook.Tab', 
                       padding=[20, 10], 
                       font=("MS UI Gothic", 10, "bold"),
                       background="#D0D0D0",
                       foreground="#000000")
        style.map('TNotebook.Tab',
                 background=[('selected', self.panel_color)],
                 foreground=[('selected', '#000000')])
        
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        # サーバータブ
        server_frame = tk.Frame(notebook, bg=self.panel_color)
        notebook.add(server_frame, text="  サーバー  ")
        self.create_server_tab(server_frame)
        
        # クライアントタブ
        client_frame = tk.Frame(notebook, bg=self.panel_color)
        notebook.add(client_frame, text="  クライアント  ")
        self.create_client_tab(client_frame)
        
        # ステータスバー
        status_frame = tk.Frame(self.root, bg="#D0D0D0", relief=tk.SUNKEN, bd=1)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = tk.Label(
            status_frame,
            text=" 準備完了 ",
            font=("MS UI Gothic", 9),
            bg="#D0D0D0",
            fg="#000000",
            anchor=tk.W
        )
        self.status_label.pack(fill=tk.X, padx=5, pady=2)
    
    def show_about(self):
        about_text = """FHS

Version 0.0.1 - Macintosh Edition
製作者: soramame72
"""
        messagebox.showinfo("FHSについて", about_text)
    
    def create_server_tab(self, parent):
        main_container = tk.Frame(parent, bg=self.panel_color)
        main_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # 設定フレーム
        config_frame = tk.LabelFrame(
            main_container, 
            text=" 設定 ", 
            bg=self.panel_color,
            fg="#000000",
            font=("MS UI Gothic", 10, "bold"),
            relief=tk.GROOVE,
            bd=1
        )
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 共有フォルダ
        folder_frame = tk.Frame(config_frame, bg=self.panel_color)
        folder_frame.pack(fill=tk.X, padx=10, pady=8)
        
        tk.Label(
            folder_frame, 
            text="共有フォルダ",
            bg=self.panel_color,
            fg="#000000",
            font=("MS UI Gothic", 9, "bold")
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.folder_entry = tk.Entry(
            folder_frame, 
            font=("MS UI Gothic", 9),
            relief=tk.SOLID,
            bd=1
        )
        self.folder_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        Win98Button(folder_frame, text="参照", command=self.browse_folder, width=8).pack(side=tk.LEFT)
        
        # パスワード
        password_frame = tk.Frame(config_frame, bg=self.panel_color)
        password_frame.pack(fill=tk.X, padx=10, pady=8)
        
        tk.Label(
            password_frame,
            text="パスワード",
            bg=self.panel_color,
            fg="#000000",
            font=("MS UI Gothic", 9, "bold")
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.password_entry = tk.Entry(
            password_frame,
            show="*",
            font=("MS UI Gothic", 9),
            relief=tk.SOLID,
            bd=1
        )
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        self.use_password_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            password_frame,
            text="パスワード認証を使用",
            variable=self.use_password_var,
            bg=self.panel_color,
            font=("MS UI Gothic", 9)
        ).pack(side=tk.LEFT)
        
        # ポート
        port_frame = tk.Frame(config_frame, bg=self.panel_color)
        port_frame.pack(fill=tk.X, padx=10, pady=8)
        
        tk.Label(
            port_frame,
            text="ポート番号",
            bg=self.panel_color,
            fg="#000000",
            font=("MS UI Gothic", 9, "bold")
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.port_entry = tk.Entry(
            port_frame,
            font=("MS UI Gothic", 9),
            relief=tk.SOLID,
            bd=1,
            width=15
        )
        self.port_entry.insert(0, "9999")
        self.port_entry.pack(side=tk.LEFT)
        
        # IPブロック設定
        ipban_frame = tk.Frame(config_frame, bg=self.panel_color)
        ipban_frame.pack(fill=tk.X, padx=10, pady=8)
        
        self.use_ipban_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            ipban_frame,
            text="IPブロック機能を使用（3回認証失敗で自動ブロック）",
            variable=self.use_ipban_var,
            bg=self.panel_color,
            font=("MS UI Gothic", 9)
        ).pack(side=tk.LEFT)
        
        # サーバーアドレス表示
        self.server_info_frame = tk.Frame(config_frame, bg="#FFFACD", relief=tk.SOLID, bd=1)
        self.server_info_frame.pack(fill=tk.X, padx=10, pady=10)
        
        addr_container = tk.Frame(self.server_info_frame, bg="#FFFACD")
        addr_container.pack(fill=tk.X, padx=10, pady=8)
        
        tk.Label(
            addr_container,
            text="サーバーアドレス:",
            font=("MS UI Gothic", 9, "bold"),
            bg="#FFFACD",
            fg="#000080"
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.server_address_entry = tk.Entry(
            addr_container,
            font=("MS UI Gothic", 9),
            relief=tk.SOLID,
            bd=1,
            state="readonly",
            readonlybackground="#FFFFFF"
        )
        self.server_address_entry.insert(0, "(未起動)")
        self.server_address_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        Win98Button(
            addr_container,
            text="コピー",
            command=self.copy_server_address,
            bg="#4CAF50",
            fg="#FFFFFF",
            width=8
        ).pack(side=tk.LEFT)
        
        # ボタンフレーム
        btn_frame = tk.Frame(main_container, bg=self.panel_color)
        btn_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.start_btn = Win98Button(
            btn_frame,
            text="サーバー開始",
            command=self.start_server,
            bg="#4CAF50",
            fg="#FFFFFF"
        )
        self.start_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_btn = Win98Button(
            btn_frame,
            text="サーバー停止",
            command=self.stop_server,
            bg="#F44336",
            fg="#FFFFFF",
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT)
        
        # ログフレーム
        log_frame = tk.LabelFrame(
            main_container,
            text=" ログ ",
            bg=self.panel_color,
            fg="#000000",
            font=("MS UI Gothic", 10, "bold"),
            relief=tk.GROOVE,
            bd=1
        )
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.server_log = scrolledtext.ScrolledText(
            log_frame,
            height=15,
            font=("MS UI Gothic", 9),
            bg="#FFFFFF",
            fg="#000000",
            relief=tk.SOLID,
            bd=1,
            wrap=tk.WORD
        )
        self.server_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_client_tab(self, parent):
        main_container = tk.Frame(parent, bg=self.panel_color)
        main_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # 接続設定フレーム
        config_frame = tk.LabelFrame(
            main_container,
            text=" 接続設定 ",
            bg=self.panel_color,
            fg="#000000",
            font=("MS UI Gothic", 10, "bold"),
            relief=tk.GROOVE,
            bd=1
        )
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        # サーバーアドレス
        address_frame = tk.Frame(config_frame, bg=self.panel_color)
        address_frame.pack(fill=tk.X, padx=10, pady=8)
        
        tk.Label(
            address_frame,
            text="サーバーアドレス",
            bg=self.panel_color,
            fg="#000000",
            font=("MS UI Gothic", 9, "bold")
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.address_entry = tk.Entry(
            address_frame,
            font=("MS UI Gothic", 9),
            relief=tk.SOLID,
            bd=1
        )
        self.address_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        Win98Button(
            address_frame,
            text="接続",
            command=self.connect_to_server,
            bg="#2196F3",
            fg="#FFFFFF",
            width=8
        ).pack(side=tk.LEFT)
        
        # パスワード
        password_frame = tk.Frame(config_frame, bg=self.panel_color)
        password_frame.pack(fill=tk.X, padx=10, pady=8)
        
        tk.Label(
            password_frame,
            text="パスワード",
            bg=self.panel_color,
            fg="#000000",
            font=("MS UI Gothic", 9, "bold")
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.client_password_entry = tk.Entry(
            password_frame,
            show="*",
            font=("MS UI Gothic", 9),
            relief=tk.SOLID,
            bd=1
        )
        self.client_password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        self.client_use_password_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            password_frame,
            text="パスワード認証を使用",
            variable=self.client_use_password_var,
            bg=self.panel_color,
            font=("MS UI Gothic", 9)
        ).pack(side=tk.LEFT)
        
        # ファイル一覧フレーム
        file_frame = tk.LabelFrame(
            main_container,
            text=" ファイル一覧 ",
            bg=self.panel_color,
            fg="#000000",
            font=("MS UI Gothic", 10, "bold"),
            relief=tk.GROOVE,
            bd=1
        )
        file_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        list_container = tk.Frame(file_frame, bg=self.panel_color)
        list_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        scrollbar = tk.Scrollbar(list_container)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.file_listbox = tk.Listbox(
            list_container,
            height=10,
            font=("MS UI Gothic", 9),
            relief=tk.SOLID,
            bd=1,
            bg="#FFFFFF",
            fg="#000000",
            selectbackground="#2196F3",
            selectforeground="#FFFFFF",
            selectmode=tk.EXTENDED,
            yscrollcommand=scrollbar.set
        )
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.file_listbox.yview)
        
        # 保存先とダウンロードフレーム
        action_frame = tk.Frame(main_container, bg=self.panel_color)
        action_frame.pack(fill=tk.X)
        
        save_frame = tk.Frame(action_frame, bg=self.panel_color)
        save_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        tk.Label(
            save_frame,
            text="保存先",
            bg=self.panel_color,
            fg="#000000",
            font=("MS UI Gothic", 9, "bold")
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.save_entry = tk.Entry(
            save_frame,
            font=("MS UI Gothic", 9),
            relief=tk.SOLID,
            bd=1
        )
        self.save_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        Win98Button(
            save_frame,
            text="参照",
            command=self.browse_save_folder,
            width=8
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        Win98Button(
            action_frame,
            text="選択ダウンロード",
            command=self.download_file,
            bg="#4CAF50",
            fg="#FFFFFF"
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        Win98Button(
            action_frame,
            text="全てダウンロード",
            command=self.download_all_files,
            bg="#FF9800",
            fg="#FFFFFF"
        ).pack(side=tk.LEFT)
    
    def parse_server_address(self, address_input):
        """様々な形式のアドレスをパース"""
        address_input = address_input.strip()
        
        if ':' in address_input:
            parts = address_input.split(':')
            host = parts[0]
            try:
                port = int(parts[1])
            except:
                port = 9999
        else:
            host = address_input
            port = 9999
        
        return host, port
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            return "127.0.0.1"
    
    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_entry.delete(0, tk.END)
            self.folder_entry.insert(0, folder)
    
    def browse_save_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.save_entry.delete(0, tk.END)
            self.save_entry.insert(0, folder)
    
    def copy_server_address(self):
        address = self.server_address_entry.get()
        if address and address != "(未起動)":
            self.root.clipboard_clear()
            self.root.clipboard_append(address)
            self.status_label.config(text=" アドレスをクリップボードにコピーしました")
            messagebox.showinfo("完了", "サーバーアドレスをコピーしました")
        else:
            messagebox.showwarning("警告", "サーバーが起動していません")
    
    def log_server(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.server_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.server_log.see(tk.END)
        self.status_label.config(text=f" {message}")
    
    def start_server(self):
        folder = self.folder_entry.get()
        password = self.password_entry.get()
        port_str = self.port_entry.get()
        use_password = self.use_password_var.get()
        use_ipban = self.use_ipban_var.get()
        
        if not folder:
            messagebox.showerror("エラー", "共有フォルダを指定してください")
            return
        
        if use_password and not password:
            messagebox.showerror("エラー", "パスワード認証を使用する場合はパスワードを入力してください")
            return
        
        if not Path(folder).exists():
            messagebox.showerror("エラー", f"指定されたフォルダが存在しません:\n{folder}")
            return
        
        try:
            port = int(port_str)
            if port < 1 or port > 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror("エラー", f"無効なポート番号です: {port_str}\n1～65535の範囲で指定してください")
            return
        
        def run_server():
            try:
                self.server = P2PServer(folder, password, port, use_password, use_ipban, self.log_server)
                local_ip = self.get_local_ip()
                server_addr = f"{local_ip}:{port}"
                
                self.root.after(0, lambda: self.server_address_entry.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.server_address_entry.delete(0, tk.END))
                self.root.after(0, lambda: self.server_address_entry.insert(0, server_addr))
                self.root.after(0, lambda: self.server_address_entry.config(state="readonly"))
                
                self.server.start()
            except OSError as e:
                if e.errno == 48 or e.errno == 10048:
                    self.log_server(f"[エラー] ポート{port}は既に使用中です")
                else:
                    self.log_server(f"[エラー] {str(e)}")
            except Exception as e:
                self.log_server(f"[エラー] {str(e)}")
        
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
    
    def stop_server(self):
        if self.server:
            self.server.stop()
            self.log_server("サーバー停止")
            self.server = None
            
            self.server_address_entry.config(state=tk.NORMAL)
            self.server_address_entry.delete(0, tk.END)
            self.server_address_entry.insert(0, "(未起動)")
            self.server_address_entry.config(state="readonly")
        
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
    
    def connect_to_server(self):
        address_input = self.address_entry.get()
        password = self.client_password_entry.get()
        use_password = self.client_use_password_var.get()
        
        if not address_input:
            messagebox.showerror("エラー", "サーバーアドレスを入力してください")
            return
        
        if use_password and not password:
            messagebox.showerror("エラー", "パスワード認証を使用する場合はパスワードを入力してください")
            return
        
        try:
            host, port = self.parse_server_address(address_input)
        except Exception as e:
            messagebox.showerror("エラー", f"アドレスの解析に失敗しました:\n{address_input}\n\nエラー: {str(e)}")
            return
        
        self.status_label.config(text=f" 接続中: {host}:{port}")
        
        try:
            client = P2PClient(host, port, password, use_password)
            files = client.get_file_list()
            
            self.file_listbox.delete(0, tk.END)
            self.files_data = files
            
            for f in files:
                size_mb = f["size"] / (1024 * 1024)
                self.file_listbox.insert(tk.END, f"{f['name']}  ({size_mb:.2f} MB)")
            
            self.status_label.config(text=f" 接続成功: {len(files)}ファイル")
            messagebox.showinfo("接続成功", f"{host}:{port}\n\n{len(files)}個のファイルが見つかりました")
        except Exception as e:
            self.status_label.config(text=" 接続失敗")
            messagebox.showerror("接続エラー", f"サーバーに接続できません\n\nサーバー: {host}:{port}\n\nエラー詳細:\n{type(e).__name__}: {str(e)}")
    
    def download_file(self):
        selections = self.file_listbox.curselection()
        if not selections:
            messagebox.showwarning("警告", "ダウンロードするファイルを選択してください")
            return
        
        save_path = self.save_entry.get()
        if not save_path:
            messagebox.showwarning("警告", "保存先フォルダを指定してください")
            return
        
        if not Path(save_path).exists():
            messagebox.showerror("エラー", f"保存先フォルダが存在しません:\n{save_path}")
            return
        
        address_input = self.address_entry.get()
        password = self.client_password_entry.get()
        use_password = self.client_use_password_var.get()
        
        try:
            host, port = self.parse_server_address(address_input)
        except Exception as e:
            messagebox.showerror("エラー", f"アドレスの解析に失敗しました:\n{str(e)}")
            return
        
        success_count = 0
        fail_count = 0
        
        for idx in selections:
            file_info = self.files_data[idx]
            filename = file_info["name"]
            
            max_retries = 3
            retry_count = 0
            downloaded = False
            
            while retry_count < max_retries and not downloaded:
                try:
                    self.status_label.config(text=f" ダウンロード中 ({retry_count + 1}/{max_retries}): {filename}")
                    self.root.update()
                    
                    client = P2PClient(host, port, password, use_password)
                    data = client.download_file(filename)
                    
                    save_file = Path(save_path) / Path(filename).name
                    save_file.parent.mkdir(parents=True, exist_ok=True)
                    
                    with open(save_file, "wb") as f:
                        f.write(data)
                    
                    success_count += 1
                    downloaded = True
                    time.sleep(0.1)
                    
                except Exception as e:
                    retry_count += 1
                    error_msg = f"ファイル: {filename}\nエラー: {type(e).__name__}\n{str(e)}"
                    print(f"[エラー ({retry_count}/{max_retries})] {error_msg}")
                    
                    if retry_count >= max_retries:
                        fail_count += 1
                        messagebox.showerror("ダウンロードエラー", f"ファイル: {filename}\n\n{max_retries}回リトライしましたが失敗しました。\n\nエラー: {type(e).__name__}\n{str(e)}")
                    else:
                        time.sleep(0.5)
        
        if success_count > 0 or fail_count > 0:
            self.status_label.config(text=f" 完了: {success_count}ファイル成功, {fail_count}ファイル失敗")
            messagebox.showinfo("完了", f"ダウンロード完了\n\n成功: {success_count}ファイル\n失敗: {fail_count}ファイル\n\n保存先: {save_path}")
    
    def download_all_files(self):
        if not hasattr(self, 'files_data') or not self.files_data:
            messagebox.showwarning("警告", "ファイル一覧が空です。\n先にサーバーに接続してください")
            return
        
        save_path = self.save_entry.get()
        if not save_path:
            messagebox.showwarning("警告", "保存先フォルダを指定してください")
            return
        
        if not Path(save_path).exists():
            messagebox.showerror("エラー", f"保存先フォルダが存在しません:\n{save_path}")
            return
        
        result = messagebox.askyesno(
            "確認",
            f"{len(self.files_data)}個のファイルを全てダウンロードしますか？\n\n保存先: {save_path}"
        )
        
        if not result:
            return
        
        address_input = self.address_entry.get()
        password = self.client_password_entry.get()
        use_password = self.client_use_password_var.get()
        
        try:
            host, port = self.parse_server_address(address_input)
        except Exception as e:
            messagebox.showerror("エラー", f"アドレスの解析に失敗しました:\n{str(e)}")
            return
        
        success_count = 0
        fail_count = 0
        
        for file_info in self.files_data:
            filename = file_info["name"]
            
            max_retries = 3
            retry_count = 0
            downloaded = False
            
            while retry_count < max_retries and not downloaded:
                try:
                    self.status_label.config(text=f" [{success_count + fail_count + 1}/{len(self.files_data)}] リトライ {retry_count + 1}/{max_retries}: {filename}")
                    self.root.update()
                    
                    client = P2PClient(host, port, password, use_password)
                    data = client.download_file(filename)
                    
                    save_file = Path(save_path) / filename
                    save_file.parent.mkdir(parents=True, exist_ok=True)
                    
                    with open(save_file, "wb") as f:
                        f.write(data)
                    
                    success_count += 1
                    downloaded = True
                    time.sleep(0.1)
                    
                except Exception as e:
                    retry_count += 1
                    error_msg = f"ファイル: {filename}\nエラー: {type(e).__name__}\n{str(e)}"
                    print(f"[エラー ({retry_count}/{max_retries})] {error_msg}")
                    
                    if retry_count >= max_retries:
                        fail_count += 1
                    else:
                        time.sleep(0.5)
        
        self.status_label.config(text=f" 全ダウンロード完了: {success_count}成功 / {fail_count}失敗")
        messagebox.showinfo(
            "完了",
            f"全ファイルダウンロード完了\n\n成功: {success_count}ファイル\n失敗: {fail_count}ファイル\n\n保存先: {save_path}"
        )


# ========== メイン実行 ==========
if __name__ == "__main__":
    root = tk.Tk()
    app = FHSApp(root)
    root.mainloop()
