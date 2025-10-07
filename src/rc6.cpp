#include <algorithm>

#include "rc6.hpp"

using namespace openiximg;
using namespace crypto;

// Default constructor
RC6::RC6() : rounds_(20) {
}

// Constructor with custom number of rounds
RC6::RC6(const uint8_t rounds) : rounds_(rounds) {
    if (rounds > 125) {
        throw std::invalid_argument("Number of rounds must be between 0 and 125");
    }
}

// Rotate left helper function
uint32_t RC6::rotl32(const uint32_t a, uint8_t n) {
    n &= 0x1f; // Higher rotates would not bring anything
    return ((a << n) | (a >> (32 - n)));
}

// Rotate right helper function
uint32_t RC6::rotr32(const uint32_t a, uint8_t n) {
    n &= 0x1f; // Higher rotates would not bring anything
    return ((a >> n) | (a << (32 - n)));
}

// Initialize the cipher with a key
void RC6::init(const void *key, const uint16_t keylength_bits) {
    if (key == nullptr) {
        throw std::invalid_argument("Key cannot be null");
    }

    if (keylength_bits == 0) {
        throw std::invalid_argument("Key length cannot be zero");
    }

    if (rounds_ > 125) {
        throw std::invalid_argument("Number of rounds must be between 0 and 125");
    }

    const auto *key_bytes = static_cast<const uint8_t *>(key);

    // Calculate number of 32-bit words in the key
    uint16_t c = keylength_bits / 32;
    if (keylength_bits % 32 != 0) {
        c++;
    }

    // Prepare key as array of 32-bit words
    std::vector<uint32_t> key_words(c, 0);
    for (uint16_t i = 0; i < keylength_bits / 8; ++i) {
        key_words[i / 4] |= static_cast<uint32_t>(key_bytes[i]) << (8 * (i % 4));
    }

    // Handle remaining bits if key length is not a multiple of 32
    if (keylength_bits % 32 != 0) {
        const uint8_t remaining_bits = keylength_bits % 8;
        if (remaining_bits > 0) {
            // Clear the remaining bits in the last byte
            key_words[c - 1] &= ~(0xFF << (8 * (keylength_bits / 8 % 4)));
        }
    }

    // Initialize round keys
    const uint16_t key_size = 2 * rounds_ + 4;
    round_keys_.resize(key_size);

    // Initialize S array with P32 and Q32 constants
    round_keys_[0] = P32;
    for (uint16_t i = 1; i < key_size; ++i) {
        round_keys_[i] = round_keys_[i - 1] + Q32;
    }

    // Mix the key into the round keys
    uint32_t a = 0, b = 0;
    uint16_t i = 0, j = 0;
    const uint16_t v = 3 * std::max(c, key_size);

    for (uint16_t p = 0; p < v; ++p) {
        a = round_keys_[i] = rotl32(round_keys_[i] + a + b, 3);
        b = key_words[j] = rotl32(key_words[j] + a + b, (a + b) & 0x1F);
        i = (i + 1) % key_size;
        j = (j + 1) % c;
    }
}

// Encrypt a block of data
void RC6::encrypt(void *block) const {
    if (!isInitialized()) {
        throw std::runtime_error("RC6 not initialized");
    }

    if (block == nullptr) {
        throw std::invalid_argument("Block cannot be null");
    }

    auto *data = static_cast<uint32_t *>(block);
    auto a = data[0];
    auto b = data[1];
    auto c = data[2];
    auto d = data[3];

    b += round_keys_[0];
    d += round_keys_[1];

    for (size_t i = 1; i <= rounds_; ++i) {
        const auto t = rotl32(b * (2 * b + 1), LG_W);
        const auto u = rotl32(d * (2 * d + 1), LG_W);
        a = rotl32((a ^ t), u) + round_keys_[2 * i];
        c = rotl32((c ^ u), t) + round_keys_[2 * i + 1];

        // Swap variables
        const auto temp = a;
        a = b;
        b = c;
        c = d;
        d = temp;
    }

    a += round_keys_[2 * rounds_ + 2];
    c += round_keys_[2 * rounds_ + 3];

    // Store the result back to the block
    data[0] = a;
    data[1] = b;
    data[2] = c;
    data[3] = d;
}

// Decrypt a block of data
void RC6::decrypt(void *block) const {
    if (!isInitialized()) {
        throw std::runtime_error("RC6 not initialized");
    }

    if (block == nullptr) {
        throw std::invalid_argument("Block cannot be null");
    }

    auto *data = static_cast<uint32_t *>(block);
    auto a = data[0];
    auto b = data[1];
    auto c = data[2];
    auto d = data[3];

    c -= round_keys_[2 * rounds_ + 3];
    a -= round_keys_[2 * rounds_ + 2];

    for (uint8_t i = rounds_; i > 0; --i) {
        // Swap variables
        const auto temp = a;
        a = d;
        d = c;
        c = b;
        b = temp;

        const auto u = rotl32(d * (2 * d + 1), LG_W);
        const auto t = rotl32(b * (2 * b + 1), LG_W);
        c = rotr32(c - round_keys_[2 * i + 1], t) ^ u;
        a = rotr32(a - round_keys_[2 * i], u) ^ t;
    }

    d -= round_keys_[1];
    b -= round_keys_[0];

    // Store the result back to the block
    data[0] = a;
    data[1] = b;
    data[2] = c;
    data[3] = d;
}

// Check if the cipher is initialized
bool RC6::isInitialized() const {
    return !round_keys_.empty();
}
