#pragma once
#include <winsock2.h>
#include <windows.h>
#include <map>
#include <vector>
#include <string>
#include <mutex>
#include <algorithm>
#include "../Common/XChaCha20.h"

namespace SessionManager {
    struct Session {
        uint32_t id = 0;
        SOCKET socket = INVALID_SOCKET;
        std::string ip_address;
        std::string hostname;
        std::string username;
        std::string os_version;
        uint32_t pid = 0;
        uint32_t last_beacon_time = 0;
        uint32_t beacon_interval = 5000;
        XChaCha20 encryptor;
        bool active = false;
        std::vector<uint8_t> pending_data;
    };

    struct ManagerState {
        std::map<uint32_t, Session> sessions;
        uint32_t next_id = 1;
        std::mutex mutex;
        uint8_t encryption_key[32];
        uint8_t encryption_nonce[24];
        uint32_t session_timeout_ms = 60000;
    };

    inline ManagerState g_manager;

    inline void initialize() {
        g_manager.next_id = 1;
        g_manager.session_timeout_ms = 60000;
        memcpy(g_manager.encryption_key,
            "\x8A\x1F\xC3\x7E\x92\x4B\x6D\x0F"
            "\x33\x58\xA7\xE1\x4C\x2D\x9F\x76"
            "\xB5\x08\xED\x13\x67\xCA\x82\x3A"
            "\xF0\x5E\x19\xD4\xAB\x71\x06\xCC", 32);
        memcpy(g_manager.encryption_nonce,
            "\x11\x22\x33\x44\x55\x66\x77\x88"
            "\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00"
            "\x10\x20\x30\x40\x50\x60\x70\x80", 24);
    }

    inline uint32_t add_session(SOCKET socket, const std::string& ip) {
        std::lock_guard<std::mutex> lock(g_manager.mutex);
        Session session;
        session.id = g_manager.next_id++;
        session.socket = socket;
        session.ip_address = ip;
        session.hostname = "unknown";
        session.username = "unknown";
        session.os_version = "unknown";
        session.pid = 0;
        session.last_beacon_time = GetTickCount();
        session.beacon_interval = 5000;
        session.active = true;
        session.encryptor.init(g_manager.encryption_key, g_manager.encryption_nonce);
        g_manager.sessions[session.id] = session;
        return session.id;
    }

    inline void remove_session(uint32_t id) {
        std::lock_guard<std::mutex> lock(g_manager.mutex);
        auto it = g_manager.sessions.find(id);
        if (it != g_manager.sessions.end()) {
            if (it->second.socket != INVALID_SOCKET) {
                closesocket(it->second.socket);
            }
            g_manager.sessions.erase(it);
        }
    }

    inline Session* get_session(uint32_t id) {
        std::lock_guard<std::mutex> lock(g_manager.mutex);
        auto it = g_manager.sessions.find(id);
        if (it != g_manager.sessions.end() && it->second.active) {
            return &it->second;
        }
        return nullptr;
    }

    inline std::vector<uint32_t> get_active_sessions() {
        std::lock_guard<std::mutex> lock(g_manager.mutex);
        std::vector<uint32_t> active;
        for (const auto& pair : g_manager.sessions) {
            if (pair.second.active) active.push_back(pair.first);
        }
        return active;
    }

    inline void update_beacon(uint32_t id) {
        std::lock_guard<std::mutex> lock(g_manager.mutex);
        auto it = g_manager.sessions.find(id);
        if (it != g_manager.sessions.end()) {
            it->second.last_beacon_time = GetTickCount();
        }
    }

    inline void cleanup_dead_sessions() {
        std::lock_guard<std::mutex> lock(g_manager.mutex);
        uint32_t now = GetTickCount();
        std::vector<uint32_t> to_remove;
        for (const auto& pair : g_manager.sessions) {
            if (pair.second.active && (now - pair.second.last_beacon_time) > g_manager.session_timeout_ms) {
                to_remove.push_back(pair.first);
            }
        }
        for (uint32_t id : to_remove) {
            auto it = g_manager.sessions.find(id);
            if (it != g_manager.sessions.end()) {
                closesocket(it->second.socket);
                g_manager.sessions.erase(it);
                printf("[*] Session #%u timed out\n", id);
            }
        }
    }

    inline size_t session_count() {
        std::lock_guard<std::mutex> lock(g_manager.mutex);
        return g_manager.sessions.size();
    }
}