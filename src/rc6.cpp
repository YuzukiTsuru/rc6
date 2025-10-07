/**
 * @file rc6.cpp
 * @brief Implementation file for the RC6 block cipher algorithm.
 * 
 * This file provides the implementation of the RC6 block cipher algorithm
 * as defined in the rc6.hpp header file.
 */
#include <algorithm>

#include "rc6.hpp"

using namespace openiximg;
using namespace crypto;

/**
 * @brief Default constructor for RC6 class.
 * 
 * Initializes the RC6 object with the default number of rounds (20).
 */
RC6::RC6() : rounds_(20) {
}

/**
 * @brief Constructor with custom number of rounds.
 * 
 * Initializes the RC6 object with the specified number of rounds.
 * 
 * @param rounds The number of rounds to use (must be between 0 and 125).
 * @throws std::invalid_argument if the number of rounds is greater than 125.
 */
RC6::RC6(const uint8_t rounds) : rounds_(rounds) {
    if (rounds > 125) {
        throw std::invalid_argument("Number of rounds must be between 0 and 125");
    }
}

/**
 * @brief Rotate left helper function.
 * 
 * Performs a bitwise rotate left operation on a 32-bit value.
 * 
 * @param a The 32-bit value to rotate.
 * @param n The number of bits to rotate (mod 32).
 * @return The rotated 32-bit value.
 */
uint32_t RC6::rotl32(const uint32_t a, uint8_t n) {
    n &= 0x1f; // Higher rotates would not bring anything
    return ((a << n) | (a >> (32 - n)));
}

/**
 * @brief Rotate right helper function.
 * 
 * Performs a bitwise rotate right operation on a 32-bit value.
 * 
 * @param a The 32-bit value to rotate.
 * @param n The number of bits to rotate (mod 32).
 * @return The rotated 32-bit value.
 */
uint32_t RC6::rotr32(const uint32_t a, uint8_t n) {
    n &= 0x1f; // Higher rotates would not bring anything
    return ((a >> n) | (a << (32 - n)));
}

/**
 * @brief Initialize the cipher with a key.
 * 
 * Sets up the RC6 cipher with the provided key material, expanding
 * it into round keys according to the RC6 key schedule algorithm.
 * 
 * @param key Pointer to the key data.
 * @param keylength_bits Length of the key in bits.
 * @throws std::invalid_argument if key is null or keylength_bits is zero.
 * @throws std::invalid_argument if the number of rounds is greater than 125.
 */
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

/**
 * @brief Encrypt a block of data using the RC6 algorithm.
 * 
 * Encrypts a 16-byte (128-bit) block of data using the previously
 * initialized RC6 cipher with the provided key.
 * 
 * @param block Pointer to the 16-byte block to encrypt. The block will be
 *              overwritten with the encrypted data.
 * @throws std::runtime_error if the cipher is not initialized.
 * @throws std::invalid_argument if block is null.
 */
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

/**
 * @brief Decrypt a block of data using the RC6 algorithm.
 * 
 * Decrypts a 16-byte (128-bit) block of data using the previously
 * initialized RC6 cipher with the provided key.
 * 
 * @param block Pointer to the 16-byte block to decrypt. The block will be
 *              overwritten with the decrypted data.
 * @throws std::runtime_error if the cipher is not initialized.
 * @throws std::invalid_argument if block is null.
 */
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

/**
 * @brief Check if the cipher is initialized.
 * 
 * Determines whether the RC6 cipher has been initialized with a key.
 * 
 * @return True if the cipher has been initialized with a key, false otherwise.
 */
bool RC6::isInitialized() const {
    return !round_keys_.empty();
}
