#pragma once
#include <string>
#include <vector>
#include <map>
#include <random>


class SymbolRenamer {
private:
    std::map<std::string, std::string> rename_map;
    std::mt19937 rng;
    
    std::string generate_random_name(size_t length = 8) {
        static const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
        std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);
        std::string result;
        result.reserve(length);
        result += charset[dist(rng) % 26];
        for (size_t i = 1; i < length; i++) {
            result += charset[dist(rng)];
        }
        return result;
    }

public:
    SymbolRenamer() : rng(std::random_device{}()) {}

    std::string register_symbol(const std::string& original_name) {
        if (rename_map.find(original_name) == rename_map.end()) {
            rename_map[original_name] = generate_random_name();
        }
        return rename_map[original_name];
    }

    std::string obfuscate_source(const std::string& source) {
        std::string result = source;
        for (const auto& [original, renamed] : rename_map) {
            size_t pos = 0;
            while ((pos = result.find(original, pos)) != std::string::npos) {
                bool left_boundary = (pos == 0 || !isalnum(result[pos - 1]));
                bool right_boundary = (pos + original.length() >= result.length() || 
                                       !isalnum(result[pos + original.length()]));
                if (left_boundary && right_boundary) {
                    result.replace(pos, original.length(), renamed);
                }
                pos += renamed.length();
            }
        }
        return result;
    }

    const std::map<std::string, std::string>& get_rename_map() const {
        return rename_map;
    }
};