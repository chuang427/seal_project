#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <iomanip>  // for setw

using namespace std;
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(8192));
    parms.set_plain_modulus(PlainModulus::Batching(8192, 20));

    SEALContext context(parms, true);

    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder encoder(context);

    Plaintext plain;
    encoder.encode(vector<uint64_t>{5}, plain);

    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);

    cout << "Initial value: 5" << endl;
    cout << "Initial noise budget: " << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

    // Print header
    cout << "\n" << setw(25) << "Operation" << setw(20) << "Noise Budget" << setw(20) << "Value" << endl;
    cout << string(65, '-') << endl;

    uint64_t expected_value = 5;
    for (int i = 1; i <= 10; i++) {
        cout << setw(25) << "Before multiplication " + to_string(i) << setw(20) 
             << decryptor.invariant_noise_budget(encrypted) << " bits";
        
        try {
            // Try to decrypt and show current value
            Plaintext temp_plain;
            decryptor.decrypt(encrypted, temp_plain);
            vector<uint64_t> temp_decoded;
            encoder.decode(temp_plain, temp_decoded);
            cout << setw(20) << temp_decoded[0] << endl;

            // Perform multiplication
            evaluator.multiply_inplace(encrypted, encrypted);
            expected_value = expected_value * expected_value;

            // Try to decrypt after multiplication
            decryptor.decrypt(encrypted, temp_plain);
            encoder.decode(temp_plain, temp_decoded);
            
            cout << setw(25) << "After multiplication " + to_string(i) << setw(20) 
                 << decryptor.invariant_noise_budget(encrypted) << " bits" << setw(20) 
                 << temp_decoded[0] << endl;
            
            if (temp_decoded[0] != expected_value) {
                cout << "\nWarning: Value mismatch!" << endl;
                cout << "Expected: " << expected_value << endl;
                cout << "Got: " << temp_decoded[0] << endl;
                break;
            }

        } catch (const exception &e) {
            cout << "\nError during multiplication " << i << ":" << endl;
            cout << "Exception: " << e.what() << endl;
            cout << "Last successful value: " << expected_value << endl;
            break;
        }
        cout << string(65, '-') << endl;
    }

    return 0;
}
