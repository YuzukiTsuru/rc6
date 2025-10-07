#ifndef RC6_HPP_
#define RC6_HPP_

#include <cstdint>
#include <vector>
#include <stdexcept>
#include <memory>

namespace openiximg {
    namespace crypto {
        class RC6 {
            static constexpr uint32_t P32 = 0xB7E15163; // e - 2
            static constexpr uint32_t Q32 = 0x9E3779B9; // Golden Ratio - 1
            static constexpr uint8_t LG_W = 5;

            uint8_t rounds_; // Number of rounds, default: 20
            std::vector<uint32_t> round_keys_; // The round keys

            // Rotate left helper function
            static uint32_t rotl32(uint32_t a, uint8_t n);

            // Rotate right helper function
            static uint32_t rotr32(uint32_t a, uint8_t n);

        public:
            // Default constructor
            RC6();

            // Constructor with custom number of rounds
            explicit RC6(uint8_t rounds);

            // Destructor
            ~RC6() = default;

            // Delete copy constructor and assignment operator to prevent key leakage
            RC6(const RC6 &) = delete;

            RC6 &operator=(const RC6 &) = delete;

            // Allow move operations
            RC6(RC6 &&) noexcept = default;

            RC6 &operator=(RC6 &&) noexcept = default;

            // Initialize the cipher with a key
            void init(const void *key, uint16_t keylength_bits);

            // Encrypt a block of data
            void encrypt(void *block) const;

            // Decrypt a block of data
            void decrypt(void *block) const;

            // Check if the cipher is initialized
            bool isInitialized() const;
        };
    } // namespace crypto
} // namespace openiximg

#endif /* RC6_HPP_ */
