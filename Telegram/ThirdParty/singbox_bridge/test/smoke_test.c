// Smoke test: load singbox.dll, start VLESS, do HTTP GET via SOCKS5.
// Build: gcc smoke_test.c -o smoke_test.exe -lws2_32
// Run:   smoke_test.exe

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

typedef int  (*SingboxStart_t)(const char*);
typedef int  (*SingboxStop_t)(int);
typedef int  (*SingboxGetPort_t)(int);
typedef char*(*SingboxGetUser_t)(int);
typedef char*(*SingboxGetPass_t)(int);
typedef char*(*SingboxLastError_t)(void);
typedef void (*SingboxFreeString_t)(char*);

static const char* OUTBOUND_JSON =
"{"
  "\"type\":\"vless\","
  "\"tag\":\"proxy\","
  "\"server\":\"nl.corginet.ru\","
  "\"server_port\":8443,"
  "\"uuid\":\"0777f865-0999-4f6f-9358-8bde1d16a888\","
  "\"tls\":{"
    "\"enabled\":true,"
    "\"server_name\":\"nl.corginet.ru\","
    "\"alpn\":[\"h3\",\"h2\",\"http/1.1\"],"
    "\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"}"
  "}"
"}";

static int send_all(SOCKET s, const unsigned char* buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(s, (const char*)buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

static int recv_exact(SOCKET s, unsigned char* buf, int len) {
    int got = 0;
    while (got < len) {
        int n = recv(s, (char*)buf + got, len - got, 0);
        if (n <= 0) return -1;
        got += n;
    }
    return 0;
}

// Returns 0 on success. Performs SOCKS5 user/pass auth, CONNECT to host:port.
static int socks5_connect(SOCKET s, const char* user, const char* pass,
                          const char* host, unsigned short port) {
    unsigned char buf[512];
    // Greeting: VER=5, NMETHODS=1, METHOD=2 (user/pass)
    unsigned char greet[] = {5, 1, 2};
    if (send_all(s, greet, 3) < 0) { printf("greet send fail\n"); return -1; }
    if (recv_exact(s, buf, 2) < 0) { printf("greet recv fail\n"); return -1; }
    if (buf[0] != 5 || buf[1] != 2) { printf("auth method rejected: %d %d\n", buf[0], buf[1]); return -1; }

    // User/pass subneg: VER=1, ULEN, UNAME, PLEN, PASS
    int ul = (int)strlen(user), pl = (int)strlen(pass);
    int i = 0;
    buf[i++] = 1;
    buf[i++] = (unsigned char)ul; memcpy(buf + i, user, ul); i += ul;
    buf[i++] = (unsigned char)pl; memcpy(buf + i, pass, pl); i += pl;
    if (send_all(s, buf, i) < 0) { printf("auth send fail\n"); return -1; }
    if (recv_exact(s, buf, 2) < 0) { printf("auth recv fail\n"); return -1; }
    if (buf[1] != 0) { printf("auth failed: status=%d\n", buf[1]); return -1; }

    // CONNECT: VER=5, CMD=1, RSV=0, ATYP=3 (domain), LEN, HOST, PORT(be)
    int hl = (int)strlen(host);
    i = 0;
    buf[i++] = 5; buf[i++] = 1; buf[i++] = 0; buf[i++] = 3;
    buf[i++] = (unsigned char)hl; memcpy(buf + i, host, hl); i += hl;
    buf[i++] = (unsigned char)(port >> 8);
    buf[i++] = (unsigned char)(port & 0xff);
    if (send_all(s, buf, i) < 0) { printf("connect send fail\n"); return -1; }
    // Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
    if (recv_exact(s, buf, 4) < 0) { printf("connect recv fail\n"); return -1; }
    if (buf[1] != 0) { printf("connect rejected: rep=%d\n", buf[1]); return -1; }
    int skip = 0;
    if (buf[3] == 1) skip = 4;
    else if (buf[3] == 3) { unsigned char l; if (recv_exact(s, &l, 1) < 0) return -1; skip = l; }
    else if (buf[3] == 4) skip = 16;
    else { printf("unknown atyp %d\n", buf[3]); return -1; }
    unsigned char tail[260];
    if (recv_exact(s, tail, skip + 2) < 0) { printf("tail recv fail\n"); return -1; }
    return 0;
}

int main(void) {
    HMODULE dll = LoadLibraryA("singbox.dll");
    if (!dll) { printf("LoadLibrary failed: %lu\n", GetLastError()); return 1; }

    SingboxStart_t       fStart = (SingboxStart_t)       GetProcAddress(dll, "SingboxStart");
    SingboxStop_t        fStop  = (SingboxStop_t)        GetProcAddress(dll, "SingboxStop");
    SingboxGetPort_t     fPort  = (SingboxGetPort_t)     GetProcAddress(dll, "SingboxGetPort");
    SingboxGetUser_t     fUser  = (SingboxGetUser_t)     GetProcAddress(dll, "SingboxGetUser");
    SingboxGetPass_t     fPass  = (SingboxGetPass_t)     GetProcAddress(dll, "SingboxGetPass");
    SingboxLastError_t   fErr   = (SingboxLastError_t)   GetProcAddress(dll, "SingboxLastError");
    SingboxFreeString_t  fFree  = (SingboxFreeString_t)  GetProcAddress(dll, "SingboxFreeString");
    if (!fStart || !fStop || !fPort || !fUser || !fPass || !fErr || !fFree) {
        printf("GetProcAddress failed\n"); return 1;
    }

    printf("Starting sing-box VLESS outbound...\n");
    int id = fStart(OUTBOUND_JSON);
    if (id == 0) {
        char* e = fErr(); printf("Start failed: %s\n", e); fFree(e); return 1;
    }
    int port = fPort(id);
    char* user = fUser(id);
    char* pass = fPass(id);
    printf("OK: id=%d  socks5=127.0.0.1:%d  user=%s  pass=%s\n", id, port, user, pass);

    // Give sing-box a moment to bind
    Sleep(500);

    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        printf("connect to local socks failed: %d\n", WSAGetLastError()); return 1;
    }
    printf("Connected to local SOCKS5\n");

    if (socks5_connect(s, user, pass, "api.ipify.org", 80) < 0) {
        printf("SOCKS5 handshake failed\n"); goto cleanup;
    }
    printf("SOCKS5 CONNECT to api.ipify.org:80 OK\n");

    const char* req = "GET /?format=text HTTP/1.0\r\nHost: api.ipify.org\r\nUser-Agent: smoke/1.0\r\nConnection: close\r\n\r\n";
    if (send_all(s, (const unsigned char*)req, (int)strlen(req)) < 0) {
        printf("http send failed\n"); goto cleanup;
    }
    char resp[4096]; int total = 0;
    while (total < (int)sizeof(resp) - 1) {
        int n = recv(s, resp + total, (int)sizeof(resp) - 1 - total, 0);
        if (n <= 0) break;
        total += n;
    }
    resp[total] = 0;
    printf("--- HTTP response via VLESS ---\n%s\n--- end ---\n", resp);

    const char* body = strstr(resp, "\r\n\r\n");
    if (body) {
        body += 4;
        printf(">>> External IP as seen through VLESS proxy: %s\n", body);
    }

cleanup:
    closesocket(s);
    WSACleanup();
    fFree(user); fFree(pass);
    fStop(id);
    FreeLibrary(dll);
    printf("done.\n");
    return 0;
}
