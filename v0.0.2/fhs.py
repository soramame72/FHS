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
import random

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


# ========== STUNクライアント（RFC 3489準拠の最小実装） ==========
class StunClient:
    STUN_SERVERS = [
        ("stun.l.google.com", 19302),
        ("stun1.l.google.com", 19302),
        ("stun2.l.google.com", 19302),
        ("stun.voip.blackberry.com", 3478),
    ]
    
    BINDING_REQUEST = 0x0001
    BINDING_RESPONSE = 0x0101
    MAGIC_COOKIE = 0x2112A442
    
    @staticmethod
    def get_external_address(local_port):
        """STUNを使用して外部IPアドレスとポートを取得"""
        for stun_host, stun_port in StunClient.STUN_SERVERS:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                sock.bind(('0.0.0.0', local_port))
                
                transaction_id = random.randint(0, 0xFFFFFFFFFFFFFFFFFFFFFFFF)
                request = StunClient.create_binding_request(transaction_id)
                
                sock.sendto(request, (stun_host, stun_port))
                
                data, addr = sock.recvfrom(1024)
                
                external_ip, external_port = StunClient.parse_binding_response(data, transaction_id)
                
                sock.close()
                
                if external_ip and external_port:
                    return external_ip, external_port
                    
            except Exception as e:
                print(f"STUN error with {stun_host}: {e}")
                if sock:
                    try:
                        sock.close()
                    except:
                        pass
                continue
        
        return None, None
    
    @staticmethod
    def create_binding_request(transaction_id):
        """STUNバインディングリクエストを作成"""
        msg_type = StunClient.BINDING_REQUEST
        msg_length = 0
        
        header = struct.pack('!HHI', msg_type, msg_length, StunClient.MAGIC_COOKIE)
        trans_id = transaction_id.to_bytes(12, 'big')
        
        return header + trans_id
    
    @staticmethod
    def parse_binding_response(data, expected_transaction_id):
        """STUNバインディングレスポンスを解析"""
        if len(data) < 20:
            return None, None
        
        msg_type, msg_length, magic_cookie = struct.unpack('!HHI', data[0:8])
        transaction_id = int.from_bytes(data[8:20], 'big')
        
        if msg_type != StunClient.BINDING_RESPONSE or transaction_id != expected_transaction_id:
            return None, None
        
        offset = 20
        while offset < len(data):
            if offset + 4 > len(data):
                break
            
            attr_type, attr_length = struct.unpack('!HH', data[offset:offset+4])
            offset += 4
            
            if offset + attr_length > len(data):
                break
            
            if attr_type == 0x0001 or attr_type == 0x0020:
                if attr_length >= 8:
                    family = data[offset + 1]
                    port = struct.unpack('!H', data[offset+2:offset+4])[0]
                    ip_bytes = data[offset+4:offset+8]
                    
                    if attr_type == 0x0020:
                        port ^= (StunClient.MAGIC_COOKIE >> 16)
                        ip_int = struct.unpack('!I', ip_bytes)[0]
                        ip_int ^= StunClient.MAGIC_COOKIE
                        ip_bytes = struct.pack('!I', ip_int)
                    
                    ip = '.'.join(str(b) for b in ip_bytes)
                    return ip, port
            
            offset += attr_length
            if attr_length % 4 != 0:
                offset += 4 - (attr_length % 4)
        
        return None, None


# ========== ホールパンチングマネージャー ==========
class HolePunchingManager:
    @staticmethod
    def punch_hole(local_port, remote_ip, remote_port, duration=3):
        """UDPホールパンチングを実行"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', local_port))
            sock.settimeout(0.1)
            
            message = b'FHS_PUNCH'
            end_time = time.time() + duration
            
            while time.time() < end_time:
                try:
                    sock.sendto(message, (remote_ip, remote_port))
                    time.sleep(0.1)
                    
                    try:
                        data, addr = sock.recvfrom(1024)
                        if data == b'FHS_PUNCH_ACK':
                            sock.close()
                            return True
                    except socket.timeout:
                        pass
                        
                except Exception as e:
                    print(f"Punch hole error: {e}")
            
            sock.close()
            return True
            
        except Exception as e:
            print(f"Hole punching failed: {e}")
            if sock:
                try:
                    sock.close()
                except:
                    pass
            return False


# ========== ローカルネットワーク発見 ==========
class LocalNetworkDiscovery:
    def __init__(self, port=9998):
        self.port = port
        self.broadcast_socket = None
        self.listen_socket = None
        self.running = False
        self.discovered_peers = {}
        self.callback = None
    
    def start_broadcast(self, server_port, external_info, callback):
        """ブロードキャスト送信を開始"""
        self.callback = callback
        self.running = True
        
        def broadcast_loop():
            try:
                self.broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                
                message = json.dumps({
                    "type": "FHS_ANNOUNCE",
                    "port": server_port,
                    "external_ip": external_info[0] if external_info[0] else "",
                    "external_port": external_info[1] if external_info[1] else 0
                }).encode()
                
                while self.running:
                    try:
                        self.broadcast_socket.sendto(message, ('<broadcast>', self.port))
                        time.sleep(5)
                    except Exception as e:
                        if self.running:
                            print(f"ブロードキャストエラー: {str(e)}")
                        time.sleep(1)
            except Exception as e:
                print(f"Broadcast setup error: {e}")
            finally:
                if self.broadcast_socket:
                    try:
                        self.broadcast_socket.close()
                    except:
                        pass
        
        threading.Thread(target=broadcast_loop, daemon=True).start()
    
    def start_listen(self, callback):
        """ブロードキャスト受信を開始"""
        self.callback = callback
        self.running = True
        
        def listen_loop():
            try:
                self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.listen_socket.bind(('', self.port))
                self.listen_socket.settimeout(1.0)
                
                while self.running:
                    try:
                        data, addr = self.listen_socket.recvfrom(1024)
                        message = json.loads(data.decode())
                        
                        if message.get("type") == "FHS_ANNOUNCE":
                            peer_ip = addr[0]
                            peer_port = message.get("port")
                            external_ip = message.get("external_ip")
                            external_port = message.get("external_port")
                            
                            peer_key = f"{peer_ip}:{peer_port}"
                            if peer_key not in self.discovered_peers:
                                self.discovered_peers[peer_key] = {
                                    "local": f"{peer_ip}:{peer_port}",
                                    "external": f"{external_ip}:{external_port}" if external_ip else ""
                                }
                                if self.callback:
                                    self.callback(peer_ip, peer_port, external_ip, external_port)
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if self.running:
                            print(f"受信エラー: {str(e)}")
            except Exception as e:
                print(f"Listen setup error: {e}")
            finally:
                if self.listen_socket:
                    try:
                        self.listen_socket.close()
                    except:
                        pass
        
        threading.Thread(target=listen_loop, daemon=True).start()
    
    def stop(self):
        """発見機能を停止"""
        self.running = False
        if self.broadcast_socket:
            try:
                self.broadcast_socket.close()
            except:
                pass
        if self.listen_socket:
            try:
                self.listen_socket.close()
            except:
                pass


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
        self.udp_socket = None
        self.running = False
        self.blocked_ips = set()
        self.failed_attempts = {}
    
    def start(self):
        self.running = True
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", self.port))
            self.server_socket.listen(5)
            self.log_callback(f"[起動] P2Pサーバー起動: 0.0.0.0:{self.port}")
            
            threading.Thread(target=self.udp_listener, daemon=True).start()
            
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
        except Exception as e:
            self.log_callback(f"[エラー] サーバー起動失敗: {str(e)}")
    
    def udp_listener(self):
        """UDPホールパンチングパケットを待ち受け"""
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.bind(('0.0.0.0', self.port))
            self.udp_socket.settimeout(1.0)
            
            while self.running:
                try:
                    data, addr = self.udp_socket.recvfrom(1024)
                    if data == b'FHS_PUNCH':
                        self.udp_socket.sendto(b'FHS_PUNCH_ACK', addr)
                        self.log_callback(f"[ホールパンチング] {addr[0]}:{addr[1]} からの接続準備")
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"UDP listener error: {e}")
        except Exception as e:
            self.log_callback(f"[エラー] UDP待受け失敗: {str(e)}")
        finally:
            if self.udp_socket:
                try:
                    self.udp_socket.close()
                except:
                    pass
    
    def handle_client(self, client_socket, client_address):
        client_ip = client_address[0]
        
        try:
            if self.use_ipban and client_ip in self.blocked_ips:
                self.send_response(client_socket, {"status": "error", "message": "IP Blocked"})
                self.log_callback(f"[拒否] ブロック済みIP: {client_ip}")
                return
            
            request_data = self.receive_data(client_socket)
            if not request_data:
                return
            
            request = json.loads(request_data.decode('utf-8'))
            command = request.get("command")
            
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
                    return
                
                if self.use_ipban:
                    self.failed_attempts[client_ip] = 0
            
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
            try:
                client_socket.close()
            except:
                pass
    
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
    
    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        if self.udp_socket:
            try:
                self.udp_socket.close()
            except:
                pass


# ========== P2Pクライアント ==========
class P2PClient:
    def __init__(self, host, port, password, use_password, local_port=None):
        self.host = host
        self.port = port
        self.password = password
        self.password_hash = hashlib.sha256(password.encode()).hexdigest() if password else None
        self.use_password = use_password
        self.local_port = local_port if local_port else random.randint(10000, 60000)

        def connect_with_hole_punching(self):
            """ホールパンチングを試みてからTCP接続を複数回リトライ"""
        
            # ★★★ 穴あけの直後にTCP接続を試行するため、UDPを連射する ★★★
            for _ in range(5): 
                HolePunchingManager.punch_hole(self.local_port, self.host, self.port)
                time.sleep(0.01) # 10ミリ秒待機

            # TCP接続の試行も連射して、開いた穴を捉えにいく
            max_retries = 10
            for retry_count in range(max_retries):
                try:
                    # 接続試行ごとに、穴あけUDPを再度送信する
                    HolePunchingManager.punch_hole(self.local_port, self.host, self.port)
                    time.sleep(0.01) 

                    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
                    # ソースポートをUDPと同じに固定 (前回修正の維持)
                    client_socket.bind(('0.0.0.0', self.local_port)) 
                
                    client_socket.settimeout(3) # タイムアウトを短く設定
                    client_socket.connect((self.host, self.port))
                
                    print(f"[P2P] 接続成功 (リトライ {retry_count + 1}回目)")
                    return client_socket
            
                except Exception as e:
                    # 接続拒否（Connection refused）の場合、リトライを継続
                    print(f"[P2P] 接続失敗 (リトライ {retry_count + 1}/{max_retries}): {e}")
                    time.sleep(0.5)
        
            # 最終的に失敗した場合はエラーを再送出
            raise ConnectionRefusedError(f"[Errno 61] Connection refused (Max retries reached: {max_retries})")
            
    def connect_and_send(self, request):
        client_socket = self.connect_with_hole_punching()
        
        try:
            if self.use_password:
                request["auth"] = self.password_hash
            
            self.send_data(client_socket, json.dumps(request).encode('utf-8'))
            
            response_data = self.receive_data(client_socket)
            response = json.loads(response_data.decode('utf-8'))
            
            return client_socket, response
        except Exception as e:
            try:
                client_socket.close()
            except:
                pass
            raise e
    
    def get_file_list(self):
        request = {"command": "list"}
        client_socket, response = self.connect_and_send(request)
        try:
            client_socket.close()
        except:
            pass
        
        if response.get("status") == "success":
            return response.get("files", [])
        else:
            raise Exception(response.get("message", "Unknown error"))
    
    def download_file(self, filename):
        request = {"command": "download", "filename": filename}
        client_socket, response = self.connect_and_send(request)
        
        try:
            if response.get("status") == "success":
                data = self.receive_data(client_socket)
                
                if self.use_password and self.password:
                    if CRYPTO_AVAILABLE:
                        data = Crypto.decrypt(data, self.password_hash)
                    else:
                        data = Crypto.xor_decrypt(data, self.password_hash)
                
                return data
            else:
                raise Exception(response.get("message", "Unknown error"))
        finally:
            try:
                client_socket.close()
            except:
                pass
    
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
        self.root.geometry("900x750")
        self.root.resizable(True, True)
        
        self.bg_color = "#E8E8E8"
        self.panel_color = "#F5F5F5"
        self.text_color = "#000000"
        self.title_bg = "#003366"
        self.title_fg = "#FFFFFF"
        
        self.root.configure(bg=self.bg_color)
        
        self.server = None
        self.server_thread = None
        self.discovery = LocalNetworkDiscovery()
        self.external_ip = None
        self.external_port = None
        
        # ウィンドウ閉鎖時の処理を設定
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.create_widgets()
        
        if not CRYPTO_AVAILABLE:
            messagebox.showwarning(
                "警告",
                "pycryptodome未インストール（簡易暗号化モード）\n\n推奨: pip install pycryptodome"
            )
    
    def on_closing(self):
        """アプリケーション終了時の処理"""
        # サーバーを停止
        if self.server:
            self.server.stop()
            self.server = None
        
        # ディスカバリーを停止
        self.discovery.stop()
        
        # ウィンドウを破棄
        self.root.destroy()
    
    def create_widgets(self):
        title_frame = tk.Frame(self.root, bg=self.title_bg, relief=tk.FLAT, bd=0)
        title_frame.pack(fill=tk.X, padx=0, pady=0)
        
        title_label = tk.Label(
            title_frame,
            text=" FHS ",
            font=("MS UI Gothic", 13, "bold"),
            bg=self.title_bg,
            fg=self.title_fg,
            pady=12
        )
        title_label.pack()
        
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        info_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="情報", menu=info_menu)
        info_menu.add_command(label="FHSについて", command=self.show_about)
        
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
        
        server_frame = tk.Frame(notebook, bg=self.panel_color)
        notebook.add(server_frame, text="  サーバー  ")
        self.create_server_tab(server_frame)
        
        # --- 修正箇所: 不要な重複と文法エラーを修正 ---
        client_frame = tk.Frame(notebook, bg=self.panel_color)
        notebook.add(client_frame, text="  クライアント  ")
        self.create_client_tab(client_frame)
        # ---------------------------------------------
        
        status_frame = tk.Frame(self.root, bg="#D0D0D0", relief=tk.SUNKEN, bd=1)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = tk.Label(
            status_frame,
            text=" 準備完了 (STUN + Hole Punching)",
            font=("MS UI Gothic", 9),
            bg="#D0D0D0",
            fg="#000000",
            anchor=tk.W
        )
        self.status_label.pack(fill=tk.X, padx=5, pady=2)
    
    def show_about(self):
        about_text = """FHS

Version 0.0.2 Macintosh Edition
製作者: soramame72
Webサイト http://mamechosu.s323.xrea.com/software/fhs/index.html
"""
        messagebox.showinfo("FHSについて", about_text)
    
    def create_server_tab(self, parent):
        main_container = tk.Frame(parent, bg=self.panel_color)
        main_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
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
            text="パスワード使用",
            variable=self.use_password_var,
            bg=self.panel_color,
            font=("MS UI Gothic", 9)
        ).pack(side=tk.LEFT)
        
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
        self.port_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        self.use_ipban_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            port_frame,
            text="IPブロック",
            variable=self.use_ipban_var,
            bg=self.panel_color,
            font=("MS UI Gothic", 9)
        ).pack(side=tk.LEFT, padx=(0, 20))
        
        self.use_discovery_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            port_frame,
            text="LAN内自動発見",
            variable=self.use_discovery_var,
            bg=self.panel_color,
            font=("MS UI Gothic", 9)
        ).pack(side=tk.LEFT)
        
        self.server_info_frame = tk.Frame(config_frame, bg="#FFFACD", relief=tk.SOLID, bd=1)
        self.server_info_frame.pack(fill=tk.X, padx=10, pady=10)
        
        info_container = tk.Frame(self.server_info_frame, bg="#FFFACD")
        info_container.pack(fill=tk.X, padx=10, pady=8)
        
        tk.Label(
            info_container,
            text="グローバルアドレス:",
            font=("MS UI Gothic", 9, "bold"),
            bg="#FFFACD",
            fg="#000080"
        ).grid(row=0, column=0, sticky=tk.W, padx=(0, 10), pady=2)
        
        self.external_address_entry = tk.Entry(
            info_container,
            font=("MS UI Gothic", 9),
            relief=tk.SOLID,
            bd=1,
            state="readonly",
            readonlybackground="#FFFFFF"
        )
        self.external_address_entry.insert(0, "(未取得)")
        self.external_address_entry.grid(row=0, column=1, sticky=tk.EW, padx=(0, 5), pady=2)
        
        Win98Button(
            info_container,
            text="コピー",
            command=self.copy_external_address,
            bg="#4CAF50",
            fg="#FFFFFF",
            width=8
        ).grid(row=0, column=2, pady=2)
        
        tk.Label(
            info_container,
            text="ローカルアドレス:",
            font=("MS UI Gothic", 9, "bold"),
            bg="#FFFACD",
            fg="#000080"
        ).grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=2)
        
        self.local_address_entry = tk.Entry(
            info_container,
            font=("MS UI Gothic", 9),
            relief=tk.SOLID,
            bd=1,
            state="readonly",
            readonlybackground="#FFFFFF"
        )
        self.local_address_entry.insert(0, "(未起動)")
        self.local_address_entry.grid(row=1, column=1, sticky=tk.EW, pady=2)
        
        info_container.columnconfigure(1, weight=1)
        
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
        
        global_frame = tk.Frame(config_frame, bg=self.panel_color)
        global_frame.pack(fill=tk.X, padx=10, pady=8)
        
        tk.Label(
            global_frame,
            text="グローバルIP",
            bg=self.panel_color,
            fg="#000000",
            font=("MS UI Gothic", 9, "bold")
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.global_ip_entry = tk.Entry(
            global_frame,
            font=("MS UI Gothic", 9),
            relief=tk.SOLID,
            bd=1,
            width=20
        )
        self.global_ip_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Label(
            global_frame,
            text="ポート",
            bg=self.panel_color,
            fg="#000000",
            font=("MS UI Gothic", 9, "bold")
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        self.global_port_entry = tk.Entry(
            global_frame,
            font=("MS UI Gothic", 9),
            relief=tk.SOLID,
            bd=1,
            width=10
        )
        self.global_port_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        Win98Button(
            global_frame,
            text="接続",
            command=self.connect_to_server,
            bg="#2196F3",
            fg="#FFFFFF",
            width=8
        ).pack(side=tk.LEFT)
        
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
            text="パスワード使用",
            variable=self.client_use_password_var,
            bg=self.panel_color,
            font=("MS UI Gothic", 9)
        ).pack(side=tk.LEFT)
        
        discovery_frame = tk.LabelFrame(
            main_container,
            text=" LAN内ピア発見 ",
            bg=self.panel_color,
            fg="#000000",
            font=("MS UI Gothic", 10, "bold"),
            relief=tk.GROOVE,
            bd=1
        )
        discovery_frame.pack(fill=tk.X, pady=(0, 10))
        
        discover_btn_frame = tk.Frame(discovery_frame, bg=self.panel_color)
        discover_btn_frame.pack(fill=tk.X, padx=10, pady=8)
        
        Win98Button(
            discover_btn_frame,
            text="ピアを検索",
            command=self.discover_peers,
            bg="#FF9800",
            fg="#FFFFFF"
        ).pack(side=tk.LEFT)
        
        tk.Label(
            discover_btn_frame,
            text="同一LAN内のFHSサーバーを自動検出（ダブルクリックで自動入力）",
            bg=self.panel_color,
            fg="#666666",
            font=("MS UI Gothic", 8)
        ).pack(side=tk.LEFT, padx=(10, 0))
        
        peer_list_frame = tk.Frame(discovery_frame, bg=self.panel_color)
        peer_list_frame.pack(fill=tk.X, padx=10, pady=(0, 8))
        
        peer_scrollbar = tk.Scrollbar(peer_list_frame)
        peer_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.peer_listbox = tk.Listbox(
            peer_list_frame,
            height=3,
            font=("MS UI Gothic", 9),
            relief=tk.SOLID,
            bd=1,
            bg="#FFFFFF",
            fg="#000000",
            selectbackground="#2196F3",
            selectforeground="#FFFFFF",
            yscrollcommand=peer_scrollbar.set
        )
        self.peer_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        peer_scrollbar.config(command=self.peer_listbox.yview)
        self.peer_listbox.bind('<Double-Button-1>', self.on_peer_double_click)
        
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
    
    def copy_external_address(self):
        address = self.external_address_entry.get()
        if address and address != "(未取得)":
            self.root.clipboard_clear()
            self.root.clipboard_append(address)
            self.status_label.config(text=" グローバルアドレスをコピーしました")
            messagebox.showinfo("完了", "グローバルアドレスをコピーしました")
        else:
            messagebox.showwarning("警告", "STUN情報が取得できていません")
    
    def log_server(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.server_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.server_log.see(tk.END)
        self.status_label.config(text=f" {message}")
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def start_server(self):
        folder = self.folder_entry.get()
        password = self.password_entry.get()
        port_str = self.port_entry.get()
        use_password = self.use_password_var.get()
        use_ipban = self.use_ipban_var.get()
        use_discovery = self.use_discovery_var.get()
        
        if not folder:
            messagebox.showerror("エラー", "共有フォルダを指定してください")
            return
        
        if use_password and not password:
            messagebox.showerror("エラー", "パスワードを入力してください")
            return
        
        if not Path(folder).exists():
            messagebox.showerror("エラー", f"フォルダが存在しません:\n{folder}")
            return
        
        try:
            port = int(port_str)
            if port < 1 or port > 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror("エラー", f"無効なポート番号: {port_str}")
            return
        
        self.log_server("[STUN] 外部アドレスを取得中...")
        external_ip, external_port = StunClient.get_external_address(port)
        
        if external_ip and external_port:
            self.external_ip = external_ip
            self.external_port = external_port
            self.log_server(f"[STUN] 外部: {external_ip}:{external_port}")
            
            self.external_address_entry.config(state=tk.NORMAL)
            self.external_address_entry.delete(0, tk.END)
            self.external_address_entry.insert(0, f"{external_ip}:{external_port}")
            self.external_address_entry.config(state="readonly")
        else:
            self.log_server("[STUN] 警告: 外部アドレス取得失敗")
            self.external_address_entry.config(state=tk.NORMAL)
            self.external_address_entry.delete(0, tk.END)
            self.external_address_entry.insert(0, "(取得失敗)")
            self.external_address_entry.config(state="readonly")
        
        def run_server():
            try:
                self.server = P2PServer(folder, password, port, use_password, use_ipban, self.log_server)
                local_ip = self.get_local_ip()
                
                self.root.after(0, lambda: self.local_address_entry.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.local_address_entry.delete(0, tk.END))
                self.root.after(0, lambda: self.local_address_entry.insert(0, f"{local_ip}:{port}"))
                self.root.after(0, lambda: self.local_address_entry.config(state="readonly"))
                
                if use_discovery:
                    self.discovery.start_broadcast(port, (external_ip, external_port), self.log_server)
                    self.log_server("[発見] LAN内ブロードキャスト開始")
                
                self.server.start()
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
            
            self.discovery.stop()
            
            self.external_address_entry.config(state=tk.NORMAL)
            self.external_address_entry.delete(0, tk.END)
            self.external_address_entry.insert(0, "(未取得)")
            self.external_address_entry.config(state="readonly")
            
            self.local_address_entry.config(state=tk.NORMAL)
            self.local_address_entry.delete(0, tk.END)
            self.local_address_entry.insert(0, "(未起動)")
            self.local_address_entry.config(state="readonly")
        
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
    
    def discover_peers(self):
        self.peer_listbox.delete(0, tk.END)
        self.status_label.config(text=" ピアを検索中...")
        
        def on_peer_found(ip, port, external_ip, external_port):
            display_text = f"LAN: {ip}:{port}"
            if external_ip:
                display_text += f" | 外部: {external_ip}:{external_port}"
            
            self.root.after(0, lambda: self.peer_listbox.insert(tk.END, display_text))
            self.root.after(0, lambda: self.status_label.config(text=f" ピア発見: {ip}:{port}"))
        
        self.discovery.start_listen(on_peer_found)
        
        self.root.after(10000, lambda: self.discovery.stop())
        self.root.after(10000, lambda: self.status_label.config(text=" 検索完了"))
    
    def on_peer_double_click(self, event):
        selection = self.peer_listbox.curselection()
        if selection:
            text = self.peer_listbox.get(selection[0])
            
            if " | 外部: " in text:
                external_part = text.split(" | 外部: ")[1]
                parts = external_part.split(":")
            else:
                lan_part = text.split(" |")[0].replace("LAN: ", "")
                parts = lan_part.split(":")
            
            if len(parts) == 2:
                self.global_ip_entry.delete(0, tk.END)
                self.global_ip_entry.insert(0, parts[0])
                self.global_port_entry.delete(0, tk.END)
                self.global_port_entry.insert(0, parts[1])
    
    def connect_to_server(self):
        global_ip = self.global_ip_entry.get()
        global_port = self.global_port_entry.get()
        password = self.client_password_entry.get()
        use_password = self.client_use_password_var.get()
        
        if not global_ip or not global_port:
            messagebox.showerror("エラー", "IPとポートを入力してください")
            return
        
        if use_password and not password:
            messagebox.showerror("エラー", "パスワードを入力してください")
            return
        
        try:
            port = int(global_port)
        except ValueError:
            messagebox.showerror("エラー", "無効なポート番号")
            return
        
        self.status_label.config(text=f" 接続中: {global_ip}:{port}")
        
        try:
            client = P2PClient(global_ip, port, password, use_password)
            files = client.get_file_list()
            
            self.file_listbox.delete(0, tk.END)
            self.files_data = files
            
            for f in files:
                size_mb = f["size"] / (1024 * 1024)
                self.file_listbox.insert(tk.END, f"{f['name']}  ({size_mb:.2f} MB)")
            
            self.status_label.config(text=f" 接続成功: {len(files)}ファイル")
            messagebox.showinfo("接続成功", f"{global_ip}:{port}\n\n{len(files)}個のファイル")
        except Exception as e:
            self.status_label.config(text=" 接続失敗")
            messagebox.showerror("接続エラー", f"サーバー: {global_ip}:{port}\n\nエラー: {type(e).__name__}\n{str(e)}")
    
    def download_file(self):
        selections = self.file_listbox.curselection()
        if not selections:
            messagebox.showwarning("警告", "ファイルを選択してください")
            return
        
        save_path = self.save_entry.get()
        if not save_path or not Path(save_path).exists():
            messagebox.showerror("エラー", "保存先を指定してください")
            return
        
        global_ip = self.global_ip_entry.get()
        global_port = self.global_port_entry.get()
        password = self.client_password_entry.get()
        use_password = self.client_use_password_var.get()
        
        try:
            port = int(global_port)
        except:
            messagebox.showerror("エラー", "無効なポート")
            return
        
        success_count = 0
        fail_count = 0
        
        for idx in selections:
            file_info = self.files_data[idx]
            filename = file_info["name"]
            
            for retry in range(3):
                try:
                    self.status_label.config(text=f" DL中 ({retry+1}/3): {filename}")
                    self.root.update()
                    
                    client = P2PClient(global_ip, port, password, use_password)
                    data = client.download_file(filename)
                    
                    save_file = Path(save_path) / Path(filename).name
                    save_file.parent.mkdir(parents=True, exist_ok=True)
                    
                    with open(save_file, "wb") as f:
                        f.write(data)
                    
                    success_count += 1
                    time.sleep(0.1)
                    break
                    
                except Exception as e:
                    if retry == 2:
                        fail_count += 1
                    else:
                        time.sleep(0.5)
        
        self.status_label.config(text=f" 完了: {success_count}成功 {fail_count}失敗")
        messagebox.showinfo("完了", f"成功: {success_count}\n失敗: {fail_count}\n\n保存先: {save_path}")
    
    def download_all_files(self):
        if not hasattr(self, 'files_data') or not self.files_data:
            messagebox.showwarning("警告", "先に接続してください")
            return
        
        save_path = self.save_entry.get()
        if not save_path or not Path(save_path).exists():
            messagebox.showerror("エラー", "保存先を指定してください")
            return
        
        if not messagebox.askyesno("確認", f"{len(self.files_data)}個全てDL?\n\n{save_path}"):
            return
        
        global_ip = self.global_ip_entry.get()
        global_port = self.global_port_entry.get()
        password = self.client_password_entry.get()
        use_password = self.client_use_password_var.get()
        
        try:
            port = int(global_port)
        except:
            return
        
        success_count = 0
        fail_count = 0
        
        for file_info in self.files_data:
            filename = file_info["name"]
            
            for retry in range(3):
                try:
                    self.status_label.config(text=f" [{success_count+fail_count+1}/{len(self.files_data)}] {filename}")
                    self.root.update()
                    
                    client = P2PClient(global_ip, port, password, use_password)
                    data = client.download_file(filename)
                    
                    save_file = Path(save_path) / filename
                    save_file.parent.mkdir(parents=True, exist_ok=True)
                    
                    with open(save_file, "wb") as f:
                        f.write(data)
                    
                    success_count += 1
                    time.sleep(0.1)
                    break
                    
                except Exception as e:
                    if retry == 2:
                        fail_count += 1
                    else:
                        time.sleep(0.5)
        
        self.status_label.config(text=f" 全DL完了: {success_count}成功 {fail_count}失敗")
        messagebox.showinfo("完了", f"全ファイルDL完了\n\n成功: {success_count}\n失敗: {fail_count}\n\n保存先: {save_path}")


# ========== メイン実行 ==========#
if __name__ == "__main__":
    root = tk.Tk()
    app = FHSApp(root)
    root.mainloop()
