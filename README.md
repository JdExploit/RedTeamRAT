# RedTeamRAT

pip install flask flask-cors cryptography colorama requests


x86_64-w64-mingw32-g++ -o visualrat_client.exe visualrat_client.cpp -static -static-libgcc -static-libstdc++ -s -O2 -mwindows -lws2_32 -liphlpapi -ladvapi32 -lshlwapi -luser32 -lgdi32 -lgdiplus -lcrypt32 -lpsapi -D_WIN32_WINNT=0x0601 -D_WINSOCK_DEPRECATED_NO_WARNINGS -D_CRT_SECURE_NO_WARNINGS
