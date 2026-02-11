# RedTeamRAT

pip install flask flask-cors cryptography colorama requests


x86_64-w64-mingw32-g++ -o visualrat_client.exe visualrat_client.cpp \
    -static -static-libgcc -static-libstdc++ -s -O2 \
    -mwindows -lws2_32 -liphlpapi -ladvapi32 -lshlwapi \
    -luser32 -lgdi32 -lgdiplus -lcrypt32 -lntdll -lpsapi \
    -ld3d9 -ldxgi -D_WIN32_WINNT=0x0601
