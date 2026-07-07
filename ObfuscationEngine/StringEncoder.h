#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <random>

class StringEncoder {
private:
    static constexpr uint8_t XOR_KEY = 0xAB;
    
public:
    static std::string encode(const std::string& input) {
        std::string result = input;
        for (size_t i = 0; i < result.length(); i++) {
            result[i] ^= XOR_KEY;
            result[i] = (result[i] << 3) | (result[i] >> 5);
        }
        return result;
    }

    static std::string decode(const std::string& encoded) {
        std::string result = encoded;
        for (size_t i = 0; i < result.length(); i++) {
            result[i] = (result[i] >> 3) | (result[i] << 5);
            result[i] ^= XOR_KEY;
        }
        return result;
    }

    static std::string ENC(const std::string& s) {
        return decode(s);
    }

    static constexpr uint32_t hash_api_name(const char* name) {
        uint32_t hash = 0x811C9DC5;
        while (*name) {
            hash ^= static_cast<uint8_t>(*name++);
            hash *= 0x01000193;
        }
        return hash;
    }
};

static_assert(StringEncoder::hash_api_name("NtAllocateVirtualMemory") == 0xE5C2B8A3, 
              "API hash mismatch");