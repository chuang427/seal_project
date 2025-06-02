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

int main() {
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(8192));
    parms.set_plain_modulus(4096); // Increased to see more values before complete failure

    SEALContext context(parms, true);
    print_parameters(context);

    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    Plaintext plain("2");
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);

    cout << "\nStarting homomorphic multiplications:" << endl;
    cout << string(100, '-') << endl;
    cout << setw(15) << "Operation" 
         << setw(15) << "Value" 
         << setw(20) << "Expected"
         << setw(20) << "Noise Budget"
         << setw(20) << "Overflow Zone"
         << setw(15) << "Status" << endl;
    cout << string(100, '-') << endl;

    uint64_t expected_value = 2;
    bool overflow_detected = false;
    int initial_noise = decryptor.invariant_noise_budget(encrypted);
    
    for (int i = 0; i <= 7; i++) {
        Plaintext temp_plain;
        string decrypted_value;
        string status;
        int noise_budget = 0;

        try {
            noise_budget = decryptor.invariant_noise_budget(encrypted);
        } catch (...) {
            noise_budget = 0;
        }

        try {
            // Always attempt decryption, even after overflow
            decryptor.decrypt(encrypted, temp_plain);
            decrypted_value = temp_plain.to_string();
            
            // Check if the decrypted value matches expected value
            uint64_t decrypted_num = stoull(decrypted_value);
            if (decrypted_num != expected_value) {
                status = "CORRUPTED";
                overflow_detected = true;
            } else {
                status = overflow_detected ? "CORRUPTED" : "OK";
            }
        } catch (const exception &e) {
            decrypted_value = "FAILED";
            status = "ERROR";
            overflow_detected = true;
        }

        string zone = (noise_budget < initial_noise / 3) ? "DANGER" : 
                     (noise_budget < initial_noise * 2/3) ? "WARNING" : "SAFE";

        // Print status for this iteration
        cout << setw(15) << "2^" + to_string(1 << i)
             << setw(15) << decrypted_value
             << setw(20) << expected_value
             << setw(20) << (noise_budget > 0 ? to_string(noise_budget) + " bits" : "0 bits")
             << setw(20) << zone
             << setw(15) << status << endl;

        if (i < 7) { // Skip last multiplication
            try {
                evaluator.multiply_inplace(encrypted, encrypted);
                expected_value = expected_value * expected_value;
            } catch (const exception &e) {
                cout << "\nMultiplication failed at step " << i + 1 << endl;
                cout << "Error: " << e.what() << endl;
                break;
            }
        }
    }

    cout << "\nThis demonstrates the Ciphertext Overflow Trap:" << endl;
    cout << "1. Each multiplication increases the noise level" << endl;
    cout << "2. When noise exceeds the budget, we enter the overflow detection zone" << endl;
    cout << "3. The plaintext modulus p (4096) determines the overflow boundary" << endl;
    cout << "4. After overflow, decryption produces corrupted values (if it works at all)" << endl;
    cout << "5. This matches the 'Attacked c' region in the diagram where values exceed p" << endl;
    cout << "6. The corrupted values demonstrate the 'mod p' operation in the diagram" << endl;

    return 0;
}
