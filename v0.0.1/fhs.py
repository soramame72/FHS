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
from pathlib import Path
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote, quote
import urllib.request
import socket

# 暗号化関連（標準ライブラリのみ使用）
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Protocol.KDF import PBKDF2
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# ========== 暗号化ユーティリティ ==========
class SimpleCrypto:
    """簡易暗号化（pycryptodomがない場合の代替）"""
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


# ========== HTTPサーバーハンドラ ==========
class FHSHandler(BaseHTTPRequestHandler):
    shared_folder = None
    password_hash = None
    blocked_ips = set()
    failed_attempts = {}
    log_callback = None
    
    def log_message(self, format, *args):
        pass
    
    def do_GET(self):
        client_ip = self.client_address[0]
        
        if client_ip in self.blocked_ips:
            self.send_error(403, "IP Blocked")
            if self.log_callback:
                self.log_callback(f"[拒否] ブロック済みIP: {client_ip}")
            return
        
        auth = self.headers.get("Authorization", "")
        if auth != self.password_hash:
            self.failed_attempts[client_ip] = self.failed_attempts.get(client_ip, 0) + 1
            if self.failed_attempts[client_ip] >= 3:
                self.blocked_ips.add(client_ip)
                if self.log_callback:
                    self.log_callback(f"[警告] IP自動ブロック: {client_ip}")
            self.send_error(403, "Unauthorized")
            if self.log_callback:
                self.log_callback(f"[拒否] 認証失敗 ({self.failed_attempts[client_ip]}/3): {client_ip}")
            return
        
        self.failed_attempts[client_ip] = 0
        
        if self.path == "/files":
            files = []
            for item in Path(self.shared_folder).rglob("*"):
                if item.is_file():
                    rel_path = item.relative_to(self.shared_folder)
                    files.append({
                        "name": str(rel_path).replace("\\", "/"),
                        "size": item.stat().st_size
                    })
            
            response = json.dumps(files).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(response))
            self.end_headers()
            self.wfile.write(response)
            
            if self.log_callback:
                self.log_callback(f"[接続] ファイル一覧送信: {client_ip} ({len(files)}ファイル)")
        
        elif self.path.startswith("/download/"):
            filename = unquote(self.path[10:])
            
            # パスの正規化とセキュリティチェック
            try:
                file_path = (Path(self.shared_folder) / filename).resolve()
                
                # セキュリティ: 共有フォルダ外へのアクセスを防ぐ
                if not str(file_path).startswith(str(Path(self.shared_folder).resolve())):
                    self.send_error(403, "Access denied")
                    if self.log_callback:
                        self.log_callback(f"[エラー] 不正アクセス試行: {filename}")
                    return
                
                if not file_path.exists():
                    self.send_error(404, "File not found")
                    if self.log_callback:
                        self.log_callback(f"[エラー] ファイル不明: {filename}")
                    return
                
                # ファイルサイズ取得
                file_size = file_path.stat().st_size
                
                with open(file_path, "rb") as f:
                    data = f.read()
                
                encrypted = Crypto.encrypt(data, self.password_hash) if CRYPTO_AVAILABLE else Crypto.xor_encrypt(data, self.password_hash)
                
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", len(encrypted))
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                self.wfile.write(encrypted)
                self.wfile.flush()
                
                if self.log_callback:
                    size_mb = len(data) / (1024 * 1024)
                    self.log_callback(f"[送信] {filename} -> {client_ip} ({size_mb:.2f}MB)")
                    
            except Exception as e:
                self.send_error(500, f"Internal server error: {str(e)}")
                if self.log_callback:
                    self.log_callback(f"[エラー] {filename}: {type(e).__name__} - {str(e)}")


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
            if current_bg == "#00AA00" or current_bg == "#4CAF50":
                self['bg'] = "#00CC00"
            elif current_bg == "#CC0000" or current_bg == "#F44336":
                self['bg'] = "#FF0000"
            elif current_bg == "#000080" or current_bg == "#2196F3":
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
        self.root.geometry("850x650")
        self.root.resizable(True, True)
        
        # シンプルなカラー
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
            text=" 準備完了",
            font=("MS UI Gothic", 9),
            bg="#D0D0D0",
            fg="#000000",
            anchor=tk.W
        )
        self.status_label.pack(fill=tk.X, padx=5, pady=2)
    
    def show_about(self):
        about_text = """FHS

Version 0.0.1
製作者: soramame72
Webサイト http://mamechosu.s323.xrea.com/software/fhs/index.html
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
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
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
        self.port_entry.insert(0, "8888")
        self.port_entry.pack(side=tk.LEFT)
        
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
        self.client_password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
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
        address_input = re.sub(r'^https?://', '', address_input.strip())
        
        if ':' in address_input:
            parts = address_input.split(':')
            host = parts[0]
            try:
                port = int(parts[1].split('/')[0])
            except:
                port = 8888
        else:
            host = address_input.split('/')[0]
            port = 8888
        
        return host, port
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            return f"127.0.0.1"
    
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
        
        if not folder:
            messagebox.showerror("エラー", "共有フォルダを指定してください")
            return
        
        if not password:
            messagebox.showerror("エラー", "パスワードを入力してください")
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
        
        FHSHandler.shared_folder = folder
        FHSHandler.password_hash = hashlib.sha256(password.encode()).hexdigest()
        FHSHandler.log_callback = self.log_server
        
        def run_server():
            try:
                self.server = HTTPServer(("0.0.0.0", port), FHSHandler)
                local_ip = self.get_local_ip()
                server_addr = f"{local_ip}:{port}"
                
                self.root.after(0, lambda: self.server_address_entry.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.server_address_entry.delete(0, tk.END))
                self.root.after(0, lambda: self.server_address_entry.insert(0, server_addr))
                self.root.after(0, lambda: self.server_address_entry.config(state="readonly"))
                
                self.log_server(f"サーバー起動: {local_ip}:{port}")
                self.log_server(f"共有フォルダ: {folder}")
                self.log_server(f"接続待機中...")
                
                self.server.serve_forever()
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
            self.server.shutdown()
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
        
        if not address_input:
            messagebox.showerror("エラー", "サーバーアドレスを入力してください")
            return
        
        if not password:
            messagebox.showerror("エラー", "パスワードを入力してください")
            return
        
        try:
            host, port = self.parse_server_address(address_input)
        except Exception as e:
            messagebox.showerror("エラー", f"アドレスの解析に失敗しました:\n{address_input}\n\nエラー: {str(e)}")
            return
        
        url = f"http://{host}:{port}/files"
        auth_hash = hashlib.sha256(password.encode()).hexdigest()
        
        self.status_label.config(text=f" 接続中: {host}:{port}")
        
        try:
            req = urllib.request.Request(url, headers={"Authorization": auth_hash})
            with urllib.request.urlopen(req, timeout=10) as response:
                files = json.loads(response.read().decode())
                
                self.file_listbox.delete(0, tk.END)
                self.files_data = files
                
                for f in files:
                    size_mb = f["size"] / (1024 * 1024)
                    self.file_listbox.insert(tk.END, f"{f['name']}  ({size_mb:.2f} MB)")
                
                self.status_label.config(text=f" 接続成功: {len(files)}ファイル")
                messagebox.showinfo("接続成功", f"{host}:{port}\n\n{len(files)}個のファイルが見つかりました")
        except urllib.error.HTTPError as e:
            self.status_label.config(text=" 接続失敗")
            if e.code == 403:
                messagebox.showerror("認証エラー", f"パスワードが正しくありません\n\nサーバー: {host}:{port}\nHTTPステータス: {e.code}")
            elif e.code == 404:
                messagebox.showerror("エラー", f"サーバーが見つかりません\n\nサーバー: {host}:{port}\nHTTPステータス: {e.code}")
            else:
                messagebox.showerror("HTTPエラー", f"サーバー: {host}:{port}\nHTTPステータス: {e.code}\n\n{str(e)}")
        except urllib.error.URLError as e:
            self.status_label.config(text=" 接続失敗")
            messagebox.showerror("接続エラー", f"サーバーに接続できません\n\nサーバー: {host}:{port}\n\n理由:\n{str(e.reason)}")
        except socket.timeout:
            self.status_label.config(text=" 接続タイムアウト")
            messagebox.showerror("タイムアウト", f"サーバーへの接続がタイムアウトしました\n\nサーバー: {host}:{port}\n\nネットワーク接続を確認してください")
        except Exception as e:
            self.status_label.config(text=" 接続エラー")
            messagebox.showerror("エラー", f"予期しないエラーが発生しました\n\nサーバー: {host}:{port}\n\nエラー詳細:\n{type(e).__name__}: {str(e)}")
    
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
        
        try:
            host, port = self.parse_server_address(address_input)
        except Exception as e:
            messagebox.showerror("エラー", f"アドレスの解析に失敗しました:\n{str(e)}")
            return
        
        auth_hash = hashlib.sha256(password.encode()).hexdigest()
        
        success_count = 0
        fail_count = 0
        
        for idx in selections:
            file_info = self.files_data[idx]
            filename = file_info["name"]
            
            # リトライ機能付きダウンロード
            max_retries = 3
            retry_count = 0
            downloaded = False
            
            while retry_count < max_retries and not downloaded:
                # ファイル名をURLエンコード
                encoded_filename = quote(filename, safe='/')
                url = f"http://{host}:{port}/download/{encoded_filename}"
                
                try:
                    self.status_label.config(text=f" ダウンロード中 ({retry_count + 1}/{max_retries}): {filename}")
                    self.root.update()
                    
                    # ファイル名をURLエンコード
                    encoded_filename = quote(filename, safe='/')
                    req = urllib.request.Request(f"http://{host}:{port}/download/{encoded_filename}", headers={"Authorization": auth_hash})
                    req.add_header('Connection', 'keep-alive')
                    
                    with urllib.request.urlopen(req, timeout=120) as response:
                        encrypted_data = response.read()
                        
                        if CRYPTO_AVAILABLE:
                            decrypted_data = Crypto.decrypt(encrypted_data, auth_hash)
                        else:
                            decrypted_data = Crypto.xor_decrypt(encrypted_data, auth_hash)
                        
                        save_file = Path(save_path) / Path(filename).name
                        save_file.parent.mkdir(parents=True, exist_ok=True)
                        
                        with open(save_file, "wb") as f:
                            f.write(decrypted_data)
                        
                        success_count += 1
                        downloaded = True
                        
                        # 連続ダウンロード時の待機時間
                        import time
                        time.sleep(0.1)
                        
                except Exception as e:
                    retry_count += 1
                    error_msg = f"ファイル: {filename}\nエラー: {type(e).__name__}\n{str(e)}"
                    print(f"[エラー ({retry_count}/{max_retries})] {error_msg}")
                    
                    if retry_count >= max_retries:
                        fail_count += 1
                        messagebox.showerror("ダウンロードエラー", f"ファイル: {filename}\n\n{max_retries}回リトライしましたが失敗しました。\n\nエラー: {type(e).__name__}\n{str(e)}")
                    else:
                        # リトライ前に少し待機
                        import time
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
        
        try:
            host, port = self.parse_server_address(address_input)
        except Exception as e:
            messagebox.showerror("エラー", f"アドレスの解析に失敗しました:\n{str(e)}")
            return
        
        auth_hash = hashlib.sha256(password.encode()).hexdigest()
        
        success_count = 0
        fail_count = 0
        
        for file_info in self.files_data:
            filename = file_info["name"]
            
            # リトライ機能付きダウンロード
            max_retries = 3
            retry_count = 0
            downloaded = False
            
            while retry_count < max_retries and not downloaded:
                # ファイル名をURLエンコード
                encoded_filename = quote(filename, safe='/')
                url = f"http://{host}:{port}/download/{encoded_filename}"
                
                try:
                    self.status_label.config(text=f" [{success_count + fail_count + 1}/{len(self.files_data)}] リトライ {retry_count + 1}/{max_retries}: {filename}")
                    self.root.update()
                    
                    # ファイル名をURLエンコード
                    encoded_filename = quote(filename, safe='/')
                    req = urllib.request.Request(f"http://{host}:{port}/download/{encoded_filename}", headers={"Authorization": auth_hash})
                    req.add_header('Connection', 'keep-alive')
                    
                    with urllib.request.urlopen(req, timeout=120) as response:
                        encrypted_data = response.read()
                        
                        if CRYPTO_AVAILABLE:
                            decrypted_data = Crypto.decrypt(encrypted_data, auth_hash)
                        else:
                            decrypted_data = Crypto.xor_decrypt(encrypted_data, auth_hash)
                        
                        save_file = Path(save_path) / filename
                        save_file.parent.mkdir(parents=True, exist_ok=True)
                        
                        with open(save_file, "wb") as f:
                            f.write(decrypted_data)
                        
                        success_count += 1
                        downloaded = True
                        
                        # 連続ダウンロード時の待機時間
                        import time
                        time.sleep(0.1)
                        
                except Exception as e:
                    retry_count += 1
                    error_msg = f"ファイル: {filename}\nエラー: {type(e).__name__}\n{str(e)}"
                    print(f"[エラー ({retry_count}/{max_retries})] {error_msg}")
                    
                    if retry_count >= max_retries:
                        fail_count += 1
                    else:
                        # リトライ前に少し待機
                        import time
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
