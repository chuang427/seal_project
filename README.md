# SEAL Homomorphic Encryption Tests

This repository contains a series of tests demonstrating different aspects of homomorphic encryption using Microsoft's SEAL library.

## Prerequisites

- CMake 3.13 or higher
- C++17 compatible compiler
- Microsoft SEAL library (version 4.1.1)

## Installation

1. Install SEAL library:
```bash
# Clone SEAL
git clone https://github.com/microsoft/SEAL.git
cd SEAL

# Create build directory
mkdir build
cd build

# Configure and build
cmake ..
make -j

# Install (optional, but recommended)
sudo make install
```

2. Clone this repository:
```bash
git clone https://github.com/chuang427/seal_project.git
cd seal_project
```

3. Build the project:
```bash
# Create build directory
mkdir build
cd build

# Configure with CMake
cmake ..

# Build all tests
make
```

## Running the Tests

After building, all executables will be in the `build` directory. You can run them as follows:

### 1. Simple Encryption Test
```bash
cd build
./simple_encrypt
```
This will demonstrate basic encryption and addition operations.

### 2. Overflow Test
```bash
cd build
./overflow_test
```
This will show how repeated multiplications affect noise levels and when values become corrupted.

### 3. Noise Budget Attack Test
```bash
cd build
./noise_budget_attack
```
This simulates an attack by injecting multiple multiplications and shows noise budget changes.

### 4. Multiply by 2 Test
```bash
cd build
./multiply_by_2_test
```
This demonstrates noise budget consumption during legitimate operations.

## Test Files

### 1. simple_encrypt.cpp
A basic demonstration of homomorphic encryption operations.
- Shows how to encrypt two numbers (5 and 7)
- Performs encrypted addition
- Displays detailed ciphertext information
- Shows noise budget for each operation

### 2. overflow_test.cpp
Demonstrates the ciphertext overflow trap in homomorphic encryption.
- Shows how repeated multiplications affect noise levels
- Displays noise budget zones (SAFE, WARNING, DANGER)
- Demonstrates when values become corrupted
- Uses a plain modulus of 4096 to show overflow boundaries

### 3. noise_budget_attack.cpp
Simulates an attack by injecting multiple multiplications.
- Performs a legitimate calculation (100 × 10)
- Injects 100 multiplications by 1
- Shows how noise budget decreases with each operation
- Demonstrates overflow detection zones
- Matches the overflow trap diagram

### 4. multiply_by_2_test.cpp
Demonstrates noise budget consumption during legitimate operations.
- Shows initial multiplication (100 × 10)
- Demonstrates multiplying by 2
- Attempts to restore original value
- Tracks noise budget throughout operations
- Shows how noise growth makes tampering detectable

## Noise Budget Zones

All tests use the following noise budget zones:
- SAFE: >66% of original noise budget
- WARNING: 33-66% of original noise budget
- DANGER: <33% of original noise budget

## Key Parameters

The tests use these encryption parameters:
- Scheme: BFV
- Polynomial modulus degree: 8192
- Plain modulus: Varies by test
- Coefficient modulus: BFVDefault(8192)

## Troubleshooting

If you encounter build issues:

1. Make sure SEAL is properly installed:
```bash
# Check if SEAL is in your library path
ldconfig -p | grep seal
```

2. If CMake can't find SEAL:
```bash
# Try setting the SEAL path explicitly
cmake -DSEAL_ROOT=/path/to/SEAL ..
```

3. If you get compiler errors:
```bash
# Make sure you have a C++17 compatible compiler
g++ --version
# Should be 7.0 or higher
```

## Notes

- Each test demonstrates different aspects of homomorphic encryption security
- The noise budget monitoring helps detect potential tampering
- The overflow tests show how noise growth can corrupt data
- All tests include detailed output of noise levels and operation status