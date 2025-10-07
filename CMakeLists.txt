cmake_minimum_required(VERSION 3.11)

project(rc6 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add source files
add_library(rc6
    src/rc6.cpp
)

# Include directories
target_include_directories(rc6 PUBLIC
    includes
)

# Add test executable
add_executable(rc6_test
    test/rc6_test.cpp
)

# Link the RC6 library to the test executable
target_link_libraries(rc6_test PRIVATE
    rc6
)

enable_testing()

# Add a test that runs the test executable
add_test(NAME RC6Test COMMAND rc6_test)
