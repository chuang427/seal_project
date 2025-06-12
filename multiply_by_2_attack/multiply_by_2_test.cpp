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
                 
    cout << setw(25) << operation
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

    cout << "\nTesting 2x Multiplication Attack:" << endl;
    cout << string(120, '-') << endl;
    cout << setw(25) << "Operation" 
         << setw(15) << "Value" 
         << setw(15) << "Expected"
         << setw(20) << "Noise Budget"
         << setw(15) << "Noise %"
         << setw(15) << "Zone"
         << setw(15) << "Status" << endl;
    cout << string(120, '-') << endl;

    // Step 1: Perform legitimate calculation (100 × 10)
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
    
    // Decrypt and verify legitimate result
    Plaintext decrypted_legitimate;
    decryptor.decrypt(legitimate_result, decrypted_legitimate);
    uint64_t legitimate_value = decrypted_legitimate[0];
    
    print_operation_status(
        "Initial (100 × 10)", 
        legitimate_value, 
        1000, 
        legitimate_noise, 
        initial_noise, 
        "OK"
    );

    // Step 2: Attack - Multiply by 2
    Plaintext multiply_by_2;
    multiply_by_2.resize(8192);
    multiply_by_2[0] = 2;
    Ciphertext attack_multiplier;
    encryptor.encrypt(multiply_by_2, attack_multiplier);
    
    Ciphertext attacked_result = legitimate_result;
    evaluator.multiply(attacked_result, attack_multiplier, attacked_result);
    
    // Check result after multiplication by 2
    Plaintext decrypted_attack;
    int attack_noise = decryptor.invariant_noise_budget(attacked_result);
    decryptor.decrypt(attacked_result, decrypted_attack);
    uint64_t attack_value = decrypted_attack[0];
    
    print_operation_status(
        "After × 2", 
        attack_value, 
        2000, 
        attack_noise, 
        legitimate_noise, 
        attack_value == 2000 ? "OK" : "CORRUPTED"
    );

    // Step 3: Try to restore - Multiply by 1/2
    Plaintext multiply_by_half;
    multiply_by_half.resize(8192);
    multiply_by_half[0] = 1;  // Note: In integer arithmetic, this won't actually divide by 2
    Ciphertext restore_multiplier;
    encryptor.encrypt(multiply_by_half, restore_multiplier);
    
    evaluator.multiply(attacked_result, restore_multiplier, attacked_result);
    
    // Check final result
    Plaintext decrypted_final;
    int final_noise = decryptor.invariant_noise_budget(attacked_result);
    decryptor.decrypt(attacked_result, decrypted_final);
    uint64_t final_value = decrypted_final[0];
    
    string final_status;
    if (final_noise == 0) {
        final_status = "CORRUPTED";
    } else if (final_value != legitimate_value) {
        final_status = "MODIFIED";
    } else {
        final_status = "RESTORED";
    }
    
    print_operation_status(
        "After restore attempt", 
        final_value, 
        legitimate_value, 
        final_noise, 
        legitimate_noise, 
        final_status
    );

    cout << "\nAnalysis:" << endl;
    cout << "1. Initial multiplication (100×10) noise budget: " << legitimate_noise << " bits" << endl;
    cout << "2. After multiplying by 2 noise budget: " << attack_noise << " bits" << endl;
    cout << "3. Final noise budget: " << final_noise << " bits" << endl;
    cout << "4. This demonstrates that:" << endl;
    cout << "   - Each multiplication operation increases noise significantly" << endl;
    cout << "   - Even simple multiplications can lead to noise overflow" << endl;
    cout << "   - Attempting to restore the original value adds even more noise" << endl;
    cout << "   - The noise growth makes it detectable when someone tampers with encrypted data" << endl;
    
    return 0;
} 