# RC6 C++ Implementation

A modern C++ implementation of the RC6 block cipher algorithm.

## Overview

This library provides a clean, object-oriented C++ implementation of the RC6 block cipher algorithm. RC6 is a symmetric key block cipher derived from RC5, designed by Ron Rivest, Matt Robshaw, Ray Sidney, and Yiqun Lisa Yin. It was submitted to the Advanced Encryption Standard (AES) competition.

## Features

- Pure C++11 implementation
- Object-oriented design
- Exception-based error handling
- Support for custom number of rounds (1-125)
- Memory-safe implementation using STL containers
- Move semantics support
- Disabled copy operations to prevent key leakage
- Comprehensive test program

## Requirements

- CMake 3.11 or later
- C++11 compatible compiler
- Standard C++ library

## Building the Library

### Using CMake

```bash
# Create and enter the build directory
mkdir build && cd build

# Configure the project
cmake ..

# Build the library and test program
cmake --build .

# Run the test
ctest
```

## Usage Example

```cpp
#include "rc6.hpp"
#include <cstring>

int main() {
    // Create RC6 object (default is 20 rounds)
    openiximg::crypto::RC6 rc6;
    
    // Initialize with a key
    const uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    rc6.init(key, sizeof(key) * 8); // Key length in bits
    
    // Data to encrypt (must be 16 bytes for RC6-32)
    uint8_t data[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    
    // Encrypt data
    rc6.encrypt(data);
    
    // Decrypt data
    rc6.decrypt(data);
    
    return 0;
}
```

## Using Custom Number of Rounds

```cpp
// Create RC6 object with 12 rounds
openiximg::crypto::RC6 rc6_12rounds(12);

// The rest is the same as above
rc6_12rounds.init(key, key_length_bits);
rc6_12rounds.encrypt(data);
rc6_12rounds.decrypt(data);
```

## Implementation Details

- **Block Size**: 128 bits (16 bytes)
- **Key Size**: Variable, up to 2048 bits
- **Number of Rounds**: Configurable, defaults to 20
- **Word Size**: 32 bits
- **Endianness**: This implementation assumes a little-endian system

## License

This project is licensed under the GNU General Public License v2.0 - see the [LICENSE](LICENSE) file for details.
