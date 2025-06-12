#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <iomanip>

using namespace std;
using namespace seal;

void print_ciphertext(const string& label, const Ciphertext& cipher) {
    cout << "\n" << label << " ciphertext details:" << endl;
    cout << "   - Size: " << cipher.size() << " polynomials" << endl;
    cout << "   - Polynomial degree: " << cipher.poly_modulus_degree() << endl;
    cout << "   - Coeff modulus size: " << cipher.coeff_modulus_size() << " bits" << endl;
    
    // Print all polynomials and their coefficients
    for (size_t poly_index = 0; poly_index < cipher.size(); poly_index++) {
        cout << "\n   Polynomial " << poly_index << " coefficients:" << endl;
        auto poly = cipher.data(poly_index);
        
        // Print coefficients in rows of 4 for better readability
        for (size_t i = 0; i < cipher.poly_modulus_degree(); i++) {
            if (i % 4 == 0) cout << "\n   ";
            cout << setw(20) << poly[i] << " ";
        }
        cout << endl;
    }
    cout << endl;
}

int main() {
    // Set encryption parameters
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(2048);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(2048));
    parms.set_plain_modulus(PlainModulus::Batching(2048, 20)); // Supports batching

    SEALContext context(parms);

    // Generate keys
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder encoder(context);

    // Encode and encrypt two integers
    Plaintext plain1, plain2;
    encoder.encode(vector<uint64_t>{5}, plain1);
    encoder.encode(vector<uint64_t>{7}, plain2);

    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    cout << "\nFirst number (5) encrypted:";
    print_ciphertext("First number", encrypted1);
    
    cout << "\nSecond number (7) encrypted:";
    print_ciphertext("Second number", encrypted2);

    // Perform encrypted addition
    Ciphertext encrypted_result;
    evaluator.add(encrypted1, encrypted2, encrypted_result);

    cout << "\nResult after encrypted addition:";
    print_ciphertext("Addition result", encrypted_result);

    // Print noise budget for each ciphertext
    cout << "\nNoise budget in ciphertexts:" << endl;
    cout << "First number: " << decryptor.invariant_noise_budget(encrypted1) << " bits" << endl;
    cout << "Second number: " << decryptor.invariant_noise_budget(encrypted2) << " bits" << endl;
    cout << "Result: " << decryptor.invariant_noise_budget(encrypted_result) << " bits" << endl;

    // Decrypt the result
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);
    vector<uint64_t> decoded_result;
    encoder.decode(plain_result, decoded_result);

    // Output the result
    cout << "\nDecrypted result: " << decoded_result[0] << endl;

    return 0;
}
