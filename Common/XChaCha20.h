#pragma once
#include <vector>
#include <cstdint>
#include <cstring>
#include <random>


class XChaCha20 {
private:
    uint32_t state[16];
    uint8_t keystream[64];
    size_t keystream_pos;

    static constexpr uint32_t CONSTANT[4] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574  // "expand 32-byte k"
    };

    __forceinline uint32_t rotl32(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = rotl32(d, 16);
        c += d; b ^= c; b = rotl32(b, 12);
        a += b; d ^= a; d = rotl32(d, 8);
        c += d; b ^= c; b = rotl32(b, 7);
    }

    void chacha20_block() {
        uint32_t working[16];
        memcpy(working, state, sizeof(working));

        for (int i = 0; i < 10; i++) {
            quarter_round(working[0], working[4], working[8],  working[12]);
            quarter_round(working[1], working[5], working[9],  working[13]);
            quarter_round(working[2], working[6], working[10], working[14]);
            quarter_round(working[3], working[7], working[11], working[15]);
            quarter_round(working[0], working[5], working[10], working[15]);
            quarter_round(working[1], working[6], working[11], working[12]);
            quarter_round(working[2], working[7], working[8],  working[13]);
            quarter_round(working[3], working[4], working[9],  working[14]);
        }

        for (int i = 0; i < 16; i++) {
            working[i] += state[i];
        }

        memcpy(keystream, working, sizeof(keystream));
        keystream_pos = 0;

        state[12]++;
        if (state[12] == 0) state[13]++;
    }

    void hchacha20(uint32_t output[8], const uint32_t input[16]) {
        uint32_t working[16];
        memcpy(working, input, sizeof(working));

        for (int i = 0; i < 10; i++) {
            quarter_round(working[0], working[4], working[8],  working[12]);
            quarter_round(working[1], working[5], working[9],  working[13]);
            quarter_round(working[2], working[6], working[10], working[14]);
            quarter_round(working[3], working[7], working[11], working[15]);
            quarter_round(working[0], working[5], working[10], working[15]);
            quarter_round(working[1], working[6], working[11], working[12]);
            quarter_round(working[2], working[7], working[8],  working[13]);
            quarter_round(working[3], working[4], working[9],  working[14]);
        }

        output[0] = working[0];  output[1] = working[1];
        output[2] = working[2];  output[3] = working[3];
        output[4] = working[12]; output[5] = working[13];
        output[6] = working[14]; output[7] = working[15];
    }

public:
    void init(const uint8_t* key, const uint8_t* nonce) {
        uint32_t h_input[16];
        memcpy(h_input, CONSTANT, sizeof(CONSTANT));
        memcpy(h_input + 4, key, 32);
        memcpy(h_input + 12, nonce, 16);

        uint32_t subkey[8];
        hchacha20(subkey, h_input);

        memcpy(state, CONSTANT, sizeof(CONSTANT));
        memcpy(state + 4, subkey, 32);
        state[12] = 0;
        state[13] = 0;
        memcpy(state + 14, nonce + 16, 8);

        keystream_pos = 64;
    }

    void process(uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; i++) {
            if (keystream_pos >= 64) {
                chacha20_block();
            }
            data[i] ^= keystream[keystream_pos++];
        }
    }

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) {
        std::vector<uint8_t> result = plaintext;
        process(result.data(), result.size());
        return result;
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext) {
        return encrypt(ciphertext);
    }

    static std::vector<uint8_t> generate_nonce() {
        std::vector<uint8_t> nonce(24);
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dist;

        for (int i = 0; i < 3; i++) {
            uint64_t val = dist(gen);
            memcpy(nonce.data() + i * 8, &val, 8);
        }
        return nonce;
    }
};