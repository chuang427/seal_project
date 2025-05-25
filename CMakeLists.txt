cmake_minimum_required(VERSION 3.13)
project(seal_project CXX)

set(CMAKE_CXX_STANDARD 17)

# Paths to SEAL and GSL (adjust if needed)
set(SEAL_SOURCE_DIR "/Users/chang/SEAL")
set(SEAL_BUILD_DIR "/Users/chang/SEAL/build")
set(GSL_DIR "/Users/chang/GSL/include")

# Include headers
include_directories(
    ${SEAL_SOURCE_DIR}/native/src
    ${SEAL_BUILD_DIR}/native/src
    ${GSL_DIR}
)

# Add your executable
add_executable(simple_encrypt simple_encrypt.cpp)

# Link SEAL static library
target_link_libraries(simple_encrypt
    ${SEAL_BUILD_DIR}/lib/libseal-4.1.a
)
