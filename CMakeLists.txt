cmake_minimum_required(VERSION 3.12)
project(seal_overflow_test)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add SEAL directory
set(SEAL_ROOT "/Users/chang/SEAL")
set(SEAL_INCLUDE_DIRS 
    "${SEAL_ROOT}/native/src"
    "${SEAL_ROOT}/build/native/src"
    "${SEAL_ROOT}/build/thirdparty/msgsl-src/include"
)
set(SEAL_LIBRARIES "${SEAL_ROOT}/build/lib/libseal-4.1.a")

# Add executable
add_executable(overflow_test overflow_test.cpp)

# Add include directories
target_include_directories(overflow_test PRIVATE ${SEAL_INCLUDE_DIRS})

# Link against SEAL
target_link_libraries(overflow_test ${SEAL_LIBRARIES})
