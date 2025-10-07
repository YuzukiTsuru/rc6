#include <iostream>
#include <iomanip>
#include <cstring>
#include <iostream>

#include "rc6.hpp"

// Function to print a block of data in hex format
void printBlock(const uint8_t *block, const size_t size) {
    for (size_t i = 0; i < size; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(block[i]) << " ";
    }
    std::cout << std::dec << std::endl;
}

// Function to run a test case
void runTestCase(const std::string &testName,
                 const uint8_t *plaintext,
                 const uint8_t *key,
                 const uint16_t keyLengthBits,
                 const uint8_t *expectedCiphertext) {
    std::cout << testName << std::endl;
    std::cout << "===============================" << std::endl;

    // Create RC6 object with default rounds (20)
    RC6 rc6;

    // Initialize with key
    rc6.init(key, keyLengthBits);

    std::cout << "Plaintext:  ";
    printBlock(plaintext, 16);

    std::cout << "Key:        ";
    printBlock(key, keyLengthBits / 8);

    // Encrypt
    uint8_t ciphertext[16];
    std::memcpy(ciphertext, plaintext, 16);
    rc6.encrypt(ciphertext);

    std::cout << "Ciphertext: ";
    printBlock(ciphertext, 16);

    std::cout << "Expected:   ";
    printBlock(expectedCiphertext, 16);

    // Decrypt
    uint8_t decryptedtext[16];
    std::memcpy(decryptedtext, ciphertext, 16);
    rc6.decrypt(decryptedtext);

    std::cout << "Decrypted:  ";
    printBlock(decryptedtext, 16);

    // Verify ciphertext matches expected
    const bool ciphertextMatch = (std::memcmp(ciphertext, expectedCiphertext, 16) == 0);
    std::cout << "Ciphertext verification: " << (ciphertextMatch ? "PASSED" : "FAILED") << std::endl;

    // Verify decryption is correct
    const bool decryptionMatch = (std::memcmp(plaintext, decryptedtext, 16) == 0);
    std::cout << "Decryption verification: " << (decryptionMatch ? "PASSED" : "FAILED") << std::endl;

    std::cout << std::endl;
}

int main() {
    try {
        std::cout << "RC6 Test Suite" << std::endl;
        std::cout << "==============" << std::endl;
        std::cout << std::endl;

        // Test Case 1: All zeros plaintext and 128-bit key
        const uint8_t plaintext1[16] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        const uint8_t key1[16] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        const uint8_t expectedCiphertext1[16] = {
            0x8f, 0xc3, 0xa5, 0x36, 0x56, 0xb1, 0xf7, 0x78,
            0xc1, 0x29, 0xdf, 0x4e, 0x98, 0x48, 0xa4, 0x1e
        };
        runTestCase("Test Case 1: All zeros (128-bit key)", plaintext1, key1, 128, expectedCiphertext1);

        // Test Case 2: Non-zero plaintext and 128-bit key
        const uint8_t plaintext2[16] = {
            0x02, 0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79,
            0x8a, 0x9b, 0xac, 0xbd, 0xce, 0xdf, 0xe0, 0xf1
        };
        const uint8_t key2[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78
        };
        const uint8_t expectedCiphertext2[16] = {
            0x52, 0x4e, 0x19, 0x2f, 0x47, 0x15, 0xc6, 0x23,
            0x1f, 0x51, 0xf6, 0x36, 0x7e, 0xa4, 0x3f, 0x18
        };
        runTestCase("Test Case 2: Non-zero (128-bit key)", plaintext2, key2, 128, expectedCiphertext2);

        // Test Case 3: All zeros plaintext and 192-bit key
        const uint8_t key3[24] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        const uint8_t expectedCiphertext3[16] = {
            0x6c, 0xd6, 0x1b, 0xcb, 0x19, 0x0b, 0x30, 0x38,
            0x4e, 0x8a, 0x3f, 0x16, 0x86, 0x90, 0xae, 0x82
        };
        runTestCase("Test Case 3: All zeros (192-bit key)", plaintext1, key3, 192, expectedCiphertext3);

        // Test Case 4: Non-zero plaintext and 192-bit key
        const uint8_t key4[24] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
            0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0
        };
        const uint8_t expectedCiphertext4[16] = {
            0x68, 0x83, 0x29, 0xd0, 0x19, 0xe5, 0x05, 0x04,
            0x1e, 0x52, 0xe9, 0x2a, 0xf9, 0x52, 0x91, 0xd4
        };
        runTestCase("Test Case 4: Non-zero (192-bit key)", plaintext2, key4, 192, expectedCiphertext4);

        // Test Case 5: All zeros plaintext and 256-bit key
        const uint8_t key5[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        const uint8_t expectedCiphertext5[16] = {
            0x8f, 0x5f, 0xbd, 0x05, 0x10, 0xd1, 0x5f, 0xa8,
            0x93, 0xfa, 0x3f, 0xda, 0x6e, 0x85, 0x7e, 0xc2
        };
        runTestCase("Test Case 5: All zeros (256-bit key)", plaintext1, key5, 256, expectedCiphertext5);

        // Test Case 6: Non-zero plaintext and 256-bit key
        const uint8_t key6[32] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
            0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe
        };
        const uint8_t expectedCiphertext6[16] = {
            0xc8, 0x24, 0x18, 0x16, 0xf0, 0xd7, 0xe4, 0x89,
            0x20, 0xad, 0x16, 0xa1, 0x67, 0x4e, 0x5d, 0x48
        };
        runTestCase("Test Case 6: Non-zero (256-bit key)", plaintext2, key6, 256, expectedCiphertext6);

        // Test with custom number of rounds
        std::cout << "\nTesting with 12 rounds" << std::endl;
        std::cout << "==================" << std::endl;

        // Use Test Case 1 with 12 rounds
        RC6 rc6_12rounds(12);
        rc6_12rounds.init(key1, 128);

        uint8_t ciphertext12[16];
        std::memcpy(ciphertext12, plaintext1, 16);

        // Encrypt
        rc6_12rounds.encrypt(ciphertext12);
        std::cout << "Plaintext (12 rounds):  ";
        printBlock(plaintext1, 16);
        std::cout << "Ciphertext (12 rounds): ";
        printBlock(ciphertext12, 16);

        // Decrypt
        uint8_t decryptedtext12[16];
        std::memcpy(decryptedtext12, ciphertext12, 16);
        rc6_12rounds.decrypt(decryptedtext12);
        std::cout << "Decrypted (12 rounds):  ";
        printBlock(decryptedtext12, 16);

        // Verify decryption is correct
        if (std::memcmp(plaintext1, decryptedtext12, 16) == 0) {
            std::cout << "Test passed: Decryption with 12 rounds matches plaintext!" << std::endl;
        } else {
            std::cout << "Test failed: Decryption with 12 rounds does not match plaintext!" << std::endl;
        }

        std::cout << "\nAll tests completed!" << std::endl;
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
