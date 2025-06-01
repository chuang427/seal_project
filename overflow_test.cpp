#include "seal/seal.h"
#include <iostream>
#include <vector>

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

    for (int i = 1; i <= 10; i++) {
        evaluator.multiply_inplace(encrypted, encrypted);

        cout << "\nAfter multiplication " << i << ":" << endl;
        cout << "Noise budget = " << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

        Plaintext plain_result;
        try {
            decryptor.decrypt(encrypted, plain_result);
            vector<uint64_t> decoded;
            encoder.decode(plain_result, decoded);
            cout << "Decrypted value: " << decoded[0] << endl;
        } catch (const exception &e) {
            cout << "Decryption failed (likely due to overflow): " << e.what() << endl;
            break;
        }
    }

    return 0;
}
