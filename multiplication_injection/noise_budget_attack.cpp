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

void print_operation_status(const string& operation, uint64_t value, uint64_t expected, 
                          int noise_budget, int baseline_budget, const string& status) {
    double noise_percentage = (noise_budget * 100.0) / baseline_budget;
    string zone = (noise_percentage < 33) ? "DANGER" : 
                 (noise_percentage < 66) ? "WARNING" : "SAFE";
                 
    cout << setw(20) << operation
         << setw(15) << value
         << setw(15) << expected
         << setw(20) << (noise_budget > 0 ? to_string(noise_budget) + " bits" : "0 bits")
         << setw(15) << fixed << setprecision(1) << noise_percentage << "%"
         << setw(15) << zone
         << setw(15) << status << endl;
}

int main() {
    // Set up encryption parameters
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(8192));
    parms.set_plain_modulus(PlainModulus::Batching(8192, 20)); // Use batching-compatible modulus

    SEALContext context(parms, true);
    print_parameters(context);

    // Generate keys
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // Step 1: Perform legitimate calculation (100 × 10)
    cout << "\nPhase 1: Legitimate Operation (100 × 10)" << endl;
    cout << string(100, '-') << endl;
    cout << setw(20) << "Operation" 
         << setw(15) << "Value" 
         << setw(15) << "Expected"
         << setw(20) << "Noise Budget"
         << setw(15) << "Noise %"
         << setw(15) << "Zone"
         << setw(15) << "Status" << endl;
    cout << string(100, '-') << endl;

    // Encrypt operands
    uint64_t value1 = 100;
    uint64_t value2 = 10;
    Plaintext plain1, plain2;
    plain1.resize(8192);
    plain2.resize(8192);
    plain1[0] = value1;
    plain2[0] = value2;
    
    Ciphertext encrypted1, encrypted2, legitimate_result;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    // Record initial noise budget
    int initial_noise = decryptor.invariant_noise_budget(encrypted1);
    
    // Perform legitimate multiplication
    evaluator.multiply(encrypted1, encrypted2, legitimate_result);
    
    // Get noise budget after legitimate operation
    int legitimate_noise = decryptor.invariant_noise_budget(legitimate_result);
    
    // Decrypt and verify
    Plaintext decrypted_legitimate;
    decryptor.decrypt(legitimate_result, decrypted_legitimate);
    uint64_t legitimate_value = decrypted_legitimate[0];
    
    print_operation_status("100 × 10", legitimate_value, 1000, 
                          legitimate_noise, initial_noise, "OK");

    // Step 2: Attack Phase - Inject multiple multiplications
    cout << "\nPhase 2: Attack Simulation (Injecting 100 multiplications)" << endl;
    cout << string(100, '-') << endl;
    
    // Create attack value (multiply by 1 to preserve value but increase noise)
    Plaintext attack_plain;
    attack_plain.resize(8192);
    attack_plain[0] = 1;
    Ciphertext attack_value;
    encryptor.encrypt(attack_plain, attack_value);
    
    Ciphertext attacked_result = legitimate_result;
    uint64_t expected_value = legitimate_value;
    bool overflow_detected = false;
    
    for (int i = 1; i <= 100; i += 10) { // Check every 10 operations
        // Perform 10 multiplications
        for (int j = 0; j < 10 && !overflow_detected; j++) {
            try {
                evaluator.multiply_inplace(attacked_result, attack_value);
            } catch (...) {
                overflow_detected = true;
                break;
            }
        }
        
        // Check result
        Plaintext decrypted_attack;
        string status = "OK";
        uint64_t current_value = 0;
        int current_noise = 0;
        
        try {
            current_noise = decryptor.invariant_noise_budget(attacked_result);
        } catch (...) {
            current_noise = 0;
        }
        
        try {
            decryptor.decrypt(attacked_result, decrypted_attack);
            current_value = decrypted_attack[0];
            
            if (current_value != expected_value) {
                status = "CORRUPTED";
                overflow_detected = true;
            }
        } catch (...) {
            status = "ERROR";
            current_value = 0;
            overflow_detected = true;
        }
        
        print_operation_status(
            "Attack #" + to_string(i), 
            current_value,
            expected_value,
            current_noise,
            legitimate_noise,
            status
        );
        
        if (overflow_detected) break;
    }
    
    cout << "\nNoise Budget Analysis:" << endl;
    cout << "1. Initial noise budget: " << initial_noise << " bits" << endl;
    cout << "2. Legitimate operation (100×10) noise budget: " << legitimate_noise << " bits" << endl;
    cout << "3. This represents the expected noise level for this calculation" << endl;
    cout << "4. Attack attempted to corrupt data by forcing noise growth" << endl;
    cout << "5. Overflow detection zones shown match the diagram:" << endl;
    cout << "   - SAFE: >66% of legitimate noise budget" << endl;
    cout << "   - WARNING: 33-66% of legitimate noise budget" << endl;
    cout << "   - DANGER: <33% of legitimate noise budget" << endl;
    
    return 0;
} 