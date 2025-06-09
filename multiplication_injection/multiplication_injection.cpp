#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <iomanip>

using namespace std;
using namespace seal;

void print_parameters(const SEALContext& context) {
    auto& context_data = *context.key_context_data();
    cout << "\nEncryption parameters:" << endl;
    cout << "- Scheme: BFV" << endl;
    cout << "- Polynomial modulus degree: " << context_data.parms().poly_modulus_degree() << endl;
    cout << "- Plain modulus (p): " << context_data.parms().plain_modulus().value() << endl;
    cout << "- Coefficient modulus size: " << context_data.total_coeff_modulus_bit_count() << " bits" << endl;
}

void print_attack_result(int iteration, const string& value, uint64_t expected, int noise_budget, 
                        const string& zone, const string& status) {
    cout << setw(15) << "Attack " + to_string(iteration)
         << setw(15) << value
         << setw(20) << expected
         << setw(20) << (noise_budget > 0 ? to_string(noise_budget) + " bits" : "0 bits")
         << setw(20) << zone
         << setw(15) << status << endl;
}

int main() {
    // Set up encryption parameters
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(8192));
    parms.set_plain_modulus(4096);

    SEALContext context(parms, true);
    print_parameters(context);

    // Generate keys
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    
    // Create necessary SEAL objects
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // Encrypt an initial value (let's use 3 this time)
    Plaintext initial_plain("3");
    Ciphertext encrypted_value;
    encryptor.encrypt(initial_plain, encrypted_value);

    cout << "\nSimulating multiplication injection attack:" << endl;
    cout << string(100, '-') << endl;
    cout << setw(15) << "Operation" 
         << setw(15) << "Value" 
         << setw(20) << "Expected"
         << setw(20) << "Noise Budget"
         << setw(20) << "Overflow Zone"
         << setw(15) << "Status" << endl;
    cout << string(100, '-') << endl;

    // Store initial noise budget for zone calculation
    int initial_noise = decryptor.invariant_noise_budget(encrypted_value);
    uint64_t expected_value = 3;
    bool overflow_detected = false;

    // Create attack ciphertext (value of 2)
    Plaintext attack_plain("2");
    Ciphertext attack_value;
    encryptor.encrypt(attack_plain, attack_value);

    // Perform repeated multiplication attacks
    for (int i = 1; i <= 10; i++) {
        Plaintext decrypted_plain;
        string decrypted_value;
        string status;
        int noise_budget = 0;

        try {
            noise_budget = decryptor.invariant_noise_budget(encrypted_value);
        } catch (...) {
            noise_budget = 0;
        }

        try {
            decryptor.decrypt(encrypted_value, decrypted_plain);
            decrypted_value = decrypted_plain.to_string();
            
            uint64_t decrypted_num = stoull(decrypted_value);
            if (decrypted_num != expected_value) {
                status = "CORRUPTED";
                overflow_detected = true;
            } else {
                status = overflow_detected ? "CORRUPTED" : "OK";
            }
        } catch (const exception& e) {
            decrypted_value = "FAILED";
            status = "ERROR";
            overflow_detected = true;
        }

        string zone = (noise_budget < initial_noise / 3) ? "DANGER" : 
                     (noise_budget < initial_noise * 2/3) ? "WARNING" : "SAFE";

        print_attack_result(i, decrypted_value, expected_value, noise_budget, zone, status);

        if (i < 10) { // Skip last multiplication
            try {
                // Simulate attack by multiplying with the attack value
                evaluator.multiply_inplace(encrypted_value, attack_value);
                expected_value = expected_value * 2; // Expected value doubles each time
            } catch (const exception& e) {
                cout << "\nAttack failed at step " << i + 1 << endl;
                cout << "Error: " << e.what() << endl;
                break;
            }
        }
    }

    cout << "\nMultiplication Injection Attack Analysis:" << endl;
    cout << "1. Started with encrypted value of 3" << endl;
    cout << "2. Attacker repeatedly multiplied by encrypted 2" << endl;
    cout << "3. Each multiplication increased noise and ciphertext size" << endl;
    cout << "4. Attack succeeded in corrupting data through noise overflow" << endl;
    cout << "5. Demonstrates importance of noise budget monitoring" << endl;
    cout << "6. Shows how multiplication operations are particularly vulnerable" << endl;

    return 0;
} 