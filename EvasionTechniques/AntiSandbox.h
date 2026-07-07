#pragma once
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")

/**
 * Detects virtual machines and sandboxes.
 */

class AntiSandbox {
private:
    static bool check_system_resources() {
        SYSTEM_INFO sys_info;
        GetSystemInfo(&sys_info);
        if (sys_info.dwNumberOfProcessors < 2) return true;
        MEMORYSTATUSEX mem = { sizeof(MEMORYSTATUSEX) };
        GlobalMemoryStatusEx(&mem);
        return mem.ullTotalPhys < 4ULL * 1024 * 1024 * 1024;
    }

    static bool check_vm_processes() {
        const wchar_t* vm_procs[] = {
            L"vmtoolsd.exe", L"vmwaretray.exe", L"vboxservice.exe",
            L"vboxtray.exe", L"xenservice.exe"
        };
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;
        PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
        bool found = false;
        if (Process32FirstW(snap, &pe)) {
            do {
                for (auto proc : vm_procs) {
                    if (_wcsicmp(pe.szExeFile, proc) == 0) {
                        found = true;
                        break;
                    }
                }
            } while (!found && Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        return found;
    }

    static bool check_registry_artifacts() {
        const wchar_t* keys[] = {
            L"HARDWARE\\ACPI\\DSDT\\VBOX__",
            L"SOFTWARE\\VMware, Inc.\\VMware Tools"
        };
        for (auto key : keys) {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return true;
            }
        }
        return false;
    }

    static bool check_mac_address() {
        IP_ADAPTER_INFO adapters[16];
        DWORD size = sizeof(adapters);
        if (GetAdaptersInfo(adapters, &size) != ERROR_SUCCESS) return false;
        uint8_t vm_ouis[][3] = {
            {0x00,0x05,0x69}, {0x00,0x0C,0x29}, {0x00,0x50,0x56}, {0x08,0x00,0x27}
        };
        for (PIP_ADAPTER_INFO p = adapters; p; p = p->Next) {
            for (auto& oui : vm_ouis) {
                if (memcmp(p->Address, oui, 3) == 0) return true;
            }
        }
        return false;
    }

public:
    static bool is_sandboxed() {
        int score = 0;
        if (check_system_resources()) score += 2;
        if (check_vm_processes()) score += 3;
        if (check_registry_artifacts()) score += 3;
        if (check_mac_address()) score += 3;
        return score >= 3;
    }

    static void safe_exit_if_sandboxed() {
        if (is_sandboxed()) ExitProcess(0);
    }
};