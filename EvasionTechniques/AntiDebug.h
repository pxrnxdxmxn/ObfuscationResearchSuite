#pragma once
#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <intrin.h>

class AntiDebug {
private:
    static bool peb_being_debugged() {
#ifdef _WIN64
        PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
        PPEB peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
        return peb->BeingDebugged != 0;
    }

    static bool check_debug_port() {
        using NtQueryInformationProcess_t = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;
        auto nt_query = reinterpret_cast<NtQueryInformationProcess_t>(
            GetProcAddress(ntdll, "NtQueryInformationProcess"));
        if (!nt_query) return false;
        DWORD64 debug_port = 0;
        NTSTATUS status = nt_query(GetCurrentProcess(), (PROCESSINFOCLASS)7, &debug_port, sizeof(debug_port), nullptr);
        return NT_SUCCESS(status) && debug_port != 0;
    }

    static bool check_hardware_breakpoints() {
        CONTEXT ctx = { CONTEXT_DEBUG_REGISTERS };
        if (!GetThreadContext(GetCurrentThread(), &ctx)) return false;
        return (ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3) != 0;
    }

    static bool timing_check() {
        uint64_t start = __rdtsc();
        for (volatile int i = 0; i < 1000; i++) __nop();
        uint64_t end = __rdtsc();
        return (end - start) > 100000;
    }

public:
    static bool detect_and_react() {
        bool detected = false;
        detected |= peb_being_debugged();
        detected |= check_debug_port();
        detected |= check_hardware_breakpoints();
        detected |= timing_check();

        if (detected) {
            __try {
                __ud2();
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                char trash[4096];
                memset(trash, 0xCC, sizeof(trash));
                void (*func)() = reinterpret_cast<void(*)()>(&trash);
                func();
            }
        }
        return detected;
    }
};