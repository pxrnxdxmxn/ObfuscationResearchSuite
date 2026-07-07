#pragma once
#include <string>
#include <windows.h>

class MetadataStripper {
public:
    
    struct StripOptions {
        bool remove_pdb_path = true;       
        bool zero_timestamp = true;         
        bool rename_sections = true;        
        bool remove_rich_header = true;     
        bool strip_debug_directory = true;  
        bool spoof_compiler = true;         
    };

    
    bool apply_stripping(HMODULE h_module, const StripOptions& options) {
        PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(h_module);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<uint8_t*>(h_module) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

       
        if (options.zero_timestamp) {
            nt->FileHeader.TimeDateStamp = 0;
        }


        if (options.strip_debug_directory) {
            IMAGE_DATA_DIRECTORY& debug_dir = 
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
            ZeroMemory(&debug_dir, sizeof(IMAGE_DATA_DIRECTORY));
        }


        if (options.rename_sections) {
            PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
            static const char* fake_names[] = {".code", ".dat", ".cfg", ".map"};
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections && i < 4; i++) {
                memset(section[i].Name, 0, IMAGE_SIZEOF_SHORT_NAME);
                memcpy(section[i].Name, fake_names[i], strlen(fake_names[i]));
            }
        }

        if (options.spoof_compiler) {
            nt->OptionalHeader.MajorLinkerVersion = 14;
            nt->OptionalHeader.MinorLinkerVersion = 0;
        }

        return true;
    }

    std::string get_strip_report(const StripOptions& options) {
        std::string report = "[METADATA STRIP REPORT]\n";
        if (options.remove_pdb_path) report += "  - PDB path: REMOVED\n";
        if (options.zero_timestamp) report += "  - Timestamp: ZEROED\n";
        if (options.rename_sections) report += "  - Section names: RANDOMIZED\n";
        if (options.remove_rich_header) report += "  - Rich header: STRIPPED\n";
        if (options.strip_debug_directory) report += "  - Debug directory: WIPED\n";
        return report;
    }
};