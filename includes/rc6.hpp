/**
 * @file rc6.hpp
 * @brief Header file for the RC6 block cipher implementation.
 * 
 * This file provides a C++ implementation of the RC6 block cipher algorithm.
 * RC6 is a symmetric key block cipher derived from RC5, designed by Ron Rivest,
 * Matt Robshaw, Ray Sidney, and Yiqun Lisa Yin.
 */
#ifndef RC6_HPP_
#define RC6_HPP_

#include <cstdint>
#include <vector>
#include <stdexcept>
#include <cstddef>

/**
 * @class RC6
 * @brief Implementation of the RC6 block cipher algorithm.
 *
 * This class provides a modern C++ implementation of the RC6 block cipher.
 * RC6 is a 128-bit block cipher with variable key size and number of rounds.
 * This implementation is restricted to 32-bit words and assumes a little-endian system.
 */
class RC6 {
    static constexpr uint32_t P32 = 0xB7E15163; //!< Magic constant (e - 2)
    static constexpr uint32_t Q32 = 0x9E3779B9; //!< Magic constant (Golden Ratio - 1)
    static constexpr uint8_t LG_W = 5; //!< Log2 of word size (32 bits)

    uint8_t rounds_; //!< Number of rounds, default: 20
    std::vector<uint32_t> round_keys_; //!< The round keys

    /**
     * @brief Rotate left helper function.
     * @param a The value to rotate.
     * @param n The number of bits to rotate.
     * @return The rotated value.
     */
    static uint32_t rotl32(uint32_t a, uint8_t n);

    /**
     * @brief Rotate right helper function.
     * @param a The value to rotate.
     * @param n The number of bits to rotate.
     * @return The rotated value.
     */
    static uint32_t rotr32(uint32_t a, uint8_t n);

public:
    /**
     * @brief Default constructor.
     *
     * Creates an RC6 object with the default number of rounds (20).
     */
    RC6();

    /**
     * @brief Constructor with custom number of rounds.
     * @param rounds The number of rounds to use (1-125).
     * @throws std::invalid_argument if rounds is greater than 125.
     */
    explicit RC6(uint8_t rounds);

    /**
     * @brief Destructor.
     */
    ~RC6() = default;

    /**
     * @brief Copy constructor (deleted).
     *
     * Copy constructor is deleted to prevent key leakage.
     */
    RC6(const RC6 &) = delete;

    /**
     * @brief Copy assignment operator (deleted).
     *
     * Copy assignment operator is deleted to prevent key leakage.
     * @return Reference to this object.
     */
    RC6 &operator=(const RC6 &) = delete;

    /**
     * @brief Move constructor (default).
     */
    RC6(RC6 &&) noexcept = default;

    /**
     * @brief Move assignment operator (default).
     * @return Reference to this object.
     */
    RC6 &operator=(RC6 &&) noexcept = default;

    /**
     * @brief Initialize the cipher with a key.
     * @param key Pointer to the key data.
     * @param keylength_bits Length of the key in bits.
     * @throws std::invalid_argument if key is null or keylength_bits is zero.
     * @throws std::invalid_argument if rounds_ is greater than 125.
     */
    void init(const void *key, uint16_t keylength_bits);

    /**
     * @brief Encrypt a block of data.
     * @param block Pointer to the 16-byte block to encrypt.
     * @throws std::runtime_error if the cipher is not initialized.
     * @throws std::invalid_argument if block is null.
     */
    void encrypt(void *block) const;

    /**
     * @brief Decrypt a block of data.
     * @param block Pointer to the 16-byte block to decrypt.
     * @throws std::runtime_error if the cipher is not initialized.
     * @throws std::invalid_argument if block is null.
     */
    void decrypt(void *block) const;

    /**
     * @brief Check if the cipher is initialized.
     * @return True if the cipher is initialized, false otherwise.
     */
    bool isInitialized() const;
};

#endif /* RC6_HPP_ */
