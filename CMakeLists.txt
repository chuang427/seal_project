cmake_minimum_required(VERSION 3.12)
project(seal_project)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add SEAL directory
set(SEAL_ROOT "/Users/chang/SEAL")
set(GSL_ROOT "/Users/chang/GSL")
set(SEAL_INCLUDE_DIRS 
    "${SEAL_ROOT}/native/src"
    "${SEAL_ROOT}/build/native/src"
    "${GSL_ROOT}/include"
)
set(SEAL_LIBRARIES "${SEAL_ROOT}/build/lib/libseal-4.1.a")

# Add executables
add_executable(simple_encrypt simple_encrypt/simple_encrypt.cpp)
add_executable(overflow_test overflow+test/overflow_test.cpp)
add_executable(noise_budget_attack multiplication_injection/noise_budget_attack.cpp)

# Add include directories for all executables
target_include_directories(simple_encrypt PRIVATE ${SEAL_INCLUDE_DIRS})
target_include_directories(overflow_test PRIVATE ${SEAL_INCLUDE_DIRS})
target_include_directories(noise_budget_attack PRIVATE ${SEAL_INCLUDE_DIRS})

# Link against SEAL for all executables
target_link_libraries(simple_encrypt ${SEAL_LIBRARIES})
target_link_libraries(overflow_test ${SEAL_LIBRARIES})
target_link_libraries(noise_budget_attack ${SEAL_LIBRARIES}) 