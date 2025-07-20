# SEAL Homomorphic Encryption Tests

## Table of Contents
1. [Overview](#overview)
2. [Overflow Trap Demo (Recommended)](#overflow-trap-demo-recommended)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Running the Tests](#running-the-tests)
6. [Test Files](#test-files)
7. [Noise Budget Zones](#noise-budget-zones)
8. [Key Parameters](#key-parameters)
9. [Troubleshooting](#troubleshooting)
10. [Notes](#notes)

## Overview
This repository contains a series of tests demonstrating different aspects of homomorphic encryption using Microsoft's SEAL library. The highlight is a robust, practical overflow trap demo that detects overflow and corruption in encrypted computations using only public SEAL APIs.

## Overflow Trap Demo (Recommended)

### What is it?
`overflow_trap_demo.cpp` is a comprehensive demonstration of how to detect overflow and corruption in homomorphic encryption using:
- SEAL's noise budget monitoring
- Decrypted value checks
- Dynamic, operation-specific thresholds

### Why this approach?
- **Practical:** No need to patch SEAL or extract internal variables.
- **Robust:** Catches all real-world overflows/corruptions.
- **Flexible:** Thresholds can be tuned for tighter or looser detection.
- **Transparent:** Easy to understand, audit, and extend.

### How does it work? (Logical Steps)
1. **Setup**
    1.1. Set SEAL BFV encryption parameters (poly modulus degree, plain modulus, etc.)
    1.2. Generate keys and create encryptor, evaluator, and decryptor
2. **Legitimate Operations**
    2.1. Encrypt two values (e.g., 100 and 10)
    2.2. Perform and log:
        - Multiplication (100 × 10)
        - Addition (100 + 10)
        - Subtraction (100 - 10)
        - Division (simulated by multiplying by modular inverse, if possible)
    2.3. For each operation:
        - Decrypt and check the result
        - Record the noise budget after the operation
        - Print a table row with operation, expected value, decrypted value, noise budget, noise %, zone (SAFE/WARNING/DANGER), and status (OK)
3. **Dynamic Threshold Calculation**
    3.1. For each operation, set a "tight" noise threshold (e.g., 33% of the noise budget after the legitimate operation)
    3.2. This threshold is used to flag when a ciphertext is at risk of overflow
4. **Simulated Attacks**
    4.1. For each operation, simulate an attack by repeatedly applying the operation (e.g., repeated multiplication by 1, addition, subtraction, or division by modular inverse)
    4.2. After each step:
        - Decrypt and check the value
        - Check the noise budget
        - If the value is wrong, flag as CORRUPTED
        - If the noise budget drops below the threshold, flag as DANGER
        - Print a table row for each step
5. **Interpretation**
    5.1. If the value is wrong or the noise budget is too low, overflow/corruption is detected
    5.2. If both are fine, the ciphertext is safe
    5.3. The demo shows how different operations affect noise and when attacks are detected

### Thought Process
- **Why monitor noise budget?**
    - SEAL's correctness guarantee is tied to the noise budget. If it's too low, decryption may fail or produce wrong results.
- **Why check the value?**
    - Even if the noise budget is high, a tampered ciphertext may decrypt to the wrong value. This catches silent corruption.
- **Why a dynamic threshold?**
    - Different operations consume different amounts of noise. A fixed threshold is too rigid; a dynamic one adapts to the operation and parameters.
- **Why simulate attacks?**
    - To show how repeated operations (even by 1) can drive a ciphertext into overflow, and to demonstrate the effectiveness of the detection logic.

### How to Run
```bash
cd build
./overflow_trap_demo
```

### How to Interpret the Output
- Each operation and attack step is logged in a table.
- Columns:
    - Operation: What was performed
    - Value: Decrypted result
    - Expected: What the result should be
    - Noise Budget: Remaining bits
    - Noise %: Relative to baseline
    - Zone: SAFE, WARNING, DANGER (based on noise %)
    - Status: OK, CORRUPTED, DANGER, ERROR
- If you see CORRUPTED or DANGER, overflow or corruption has been detected.
- The demo also prints a summary analysis at the end.

### How to Tune Detection Tightness
- The threshold (e.g., 33%) can be adjusted in the code for tighter or looser detection.
- For maximum theoretical tightness, empirically determine the minimum safe noise budget for your parameters and set the threshold just above it.

---

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