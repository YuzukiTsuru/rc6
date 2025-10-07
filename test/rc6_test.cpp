#include <iostream>
#include <iomanip>
#include <cstring>

#include "rc6.hpp"

// Function to print a block of data in hex format
void printBlock(const uint8_t *block, const size_t size) {
    for (size_t i = 0; i < size; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(block[i]) << " ";
    }
    std::cout << std::dec << std::endl;
}

int main() {
    try {
        // Test data
        const uint8_t key[16] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        const uint8_t plaintext[16] = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
        };
        uint8_t ciphertext[16];
        uint8_t decryptedtext[16];

        // Copy plaintext to ciphertext and decryptedtext buffers
        std::memcpy(ciphertext, plaintext, sizeof(plaintext));
        std::memcpy(decryptedtext, plaintext, sizeof(plaintext));

        // Create RC6 object
        openiximg::crypto::RC6 rc6;

        // Initialize with key
        rc6.init(key, sizeof(key) * 8);

        std::cout << "RC6 Test" << std::endl;
        std::cout << "==========" << std::endl;

        std::cout << "Plaintext:  ";
        printBlock(plaintext, sizeof(plaintext));

        // Encrypt
        rc6.encrypt(ciphertext);
        std::cout << "Ciphertext: ";
        printBlock(ciphertext, sizeof(ciphertext));

        // Decrypt
        rc6.decrypt(ciphertext);
        std::cout << "Decrypted:  ";
        printBlock(ciphertext, sizeof(ciphertext));

        // Verify decryption is correct
        if (std::memcmp(plaintext, ciphertext, sizeof(plaintext)) == 0) {
            std::cout << "Test passed: Decryption matches plaintext!" << std::endl;
        } else {
            std::cout << "Test failed: Decryption does not match plaintext!" << std::endl;
        }

        // Test with custom number of rounds
        std::cout << "\nTesting with 12 rounds" << std::endl;
        std::cout << "==================" << std::endl;

        openiximg::crypto::RC6 rc6_12rounds(12);
        rc6_12rounds.init(key, sizeof(key) * 8);

        // Re-initialize decryptedtext with plaintext
        std::memcpy(decryptedtext, plaintext, sizeof(plaintext));

        // Encrypt
        rc6_12rounds.encrypt(decryptedtext);
        std::cout << "Ciphertext (12 rounds): ";
        printBlock(decryptedtext, sizeof(decryptedtext));

        // Decrypt
        rc6_12rounds.decrypt(decryptedtext);
        std::cout << "Decrypted (12 rounds):  ";
        printBlock(decryptedtext, sizeof(decryptedtext));

        // Verify decryption is correct
        if (std::memcmp(plaintext, decryptedtext, sizeof(plaintext)) == 0) {
            std::cout << "Test passed: Decryption with 12 rounds matches plaintext!" << std::endl;
        } else {
            std::cout << "Test failed: Decryption with 12 rounds does not match plaintext!" << std::endl;
        }

        return 0;
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
