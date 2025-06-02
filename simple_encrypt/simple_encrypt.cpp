#include "seal/seal.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace seal;

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

    // Perform encrypted addition
    Ciphertext encrypted_result;
    evaluator.add(encrypted1, encrypted2, encrypted_result);

    // Decrypt the result
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);
    vector<uint64_t> decoded_result;
    encoder.decode(plain_result, decoded_result);

    // Output the result
    cout << "Decrypted result: " << decoded_result[0] << endl;

    return 0;
}
