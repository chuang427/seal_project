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
    double noise_percentage = (baseline_budget > 0) ? (noise_budget * 100.0) / baseline_budget : 0.0;
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
    
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    // Record initial noise budget
    int initial_noise = decryptor.invariant_noise_budget(encrypted1);

    // --- Multiplication ---
    Ciphertext mult_result;
    evaluator.multiply(encrypted1, encrypted2, mult_result);
    int mult_noise = decryptor.invariant_noise_budget(mult_result);
    Plaintext decrypted_mult;
    decryptor.decrypt(mult_result, decrypted_mult);
    uint64_t mult_value = decrypted_mult[0];
    print_operation_status("100 × 10", mult_value, 1000, mult_noise, initial_noise, "OK");
    int mult_threshold = static_cast<int>(mult_noise * 0.33);

    // --- Addition ---
    Ciphertext add_result;
    evaluator.add(encrypted1, encrypted2, add_result);
    int add_noise = decryptor.invariant_noise_budget(add_result);
    Plaintext decrypted_add;
    decryptor.decrypt(add_result, decrypted_add);
    uint64_t add_value = decrypted_add[0];
    print_operation_status("100 + 10", add_value, 110, add_noise, initial_noise, "OK");
    int add_threshold = static_cast<int>(add_noise * 0.33);

    // --- Subtraction ---
    Ciphertext sub_result;
    evaluator.sub(encrypted1, encrypted2, sub_result);
    int sub_noise = decryptor.invariant_noise_budget(sub_result);
    Plaintext decrypted_sub;
    decryptor.decrypt(sub_result, decrypted_sub);
    uint64_t sub_value = decrypted_sub[0];
    print_operation_status("100 - 10", sub_value, 90, sub_noise, initial_noise, "OK");
    int sub_threshold = static_cast<int>(sub_noise * 0.33);

    // --- Division (simulate by multiplying by inverse if possible) ---
    // For BFV, division is not natively supported, but we can simulate division by multiplying by the modular inverse of value2 mod plain_modulus
    uint64_t plain_modulus = parms.plain_modulus().value();
    uint64_t value2_inv = 0;
    for (uint64_t i = 1; i < plain_modulus; ++i) {
        if ((value2 * i) % plain_modulus == 1) {
            value2_inv = i;
            break;
        }
    }
    if (value2_inv != 0) {
        Plaintext plain2_inv;
        plain2_inv.resize(8192);
        plain2_inv[0] = value2_inv;
        Ciphertext encrypted2_inv;
        encryptor.encrypt(plain2_inv, encrypted2_inv);
        Ciphertext div_result;
        evaluator.multiply(encrypted1, encrypted2_inv, div_result);
        int div_noise = decryptor.invariant_noise_budget(div_result);
        Plaintext decrypted_div;
        decryptor.decrypt(div_result, decrypted_div);
        uint64_t div_value = decrypted_div[0];
        print_operation_status("100 / 10", div_value, 10, div_noise, initial_noise, "OK");
        int div_threshold = static_cast<int>(div_noise * 0.33);

        // --- Simulated Attack: Division ---
        cout << "\nPhase 2: Attack Simulation (Division)" << endl;
        cout << string(100, '-') << endl;
        Ciphertext attacked_div = div_result;
        uint64_t expected_div = div_value;
        bool overflow_div = false;
        for (int i = 1; i <= 100; i += 5) {
            for (int j = 0; j < 5 && !overflow_div; j++) {
                try {
                    evaluator.multiply_inplace(attacked_div, encrypted2_inv);
                } catch (...) {
                    overflow_div = true;
                    break;
                }
            }
            Plaintext dec_attack_div;
            string status = "OK";
            uint64_t curr_val = 0;
            int curr_noise = 0;
            try { curr_noise = decryptor.invariant_noise_budget(attacked_div); } catch (...) { curr_noise = 0; }
            try {
                decryptor.decrypt(attacked_div, dec_attack_div);
                curr_val = dec_attack_div[0];
                if (curr_val != expected_div) { status = "CORRUPTED"; overflow_div = true; }
                else if (curr_noise < div_threshold) { status = "DANGER"; overflow_div = true; }
            } catch (...) { status = "ERROR"; curr_val = 0; overflow_div = true; }
            print_operation_status("Div Attack #" + to_string(i), curr_val, expected_div, curr_noise, div_noise, status);
            if (overflow_div) break;
        }
    } else {
        cout << "Division by 10 not possible (no modular inverse in this modulus)." << endl;
    }

    // --- Simulated Attack: Multiplication ---
    cout << "\nPhase 2: Attack Simulation (Multiplication)" << endl;
    cout << string(100, '-') << endl;
    Ciphertext attacked_mult = mult_result;
    uint64_t expected_mult = mult_value;
    bool overflow_mult = false;
    Plaintext attack_plain;
    attack_plain.resize(8192);
    attack_plain[0] = 1;
    Ciphertext attack_value;
    encryptor.encrypt(attack_plain, attack_value);
    for (int i = 1; i <= 100; i += 5) {
        for (int j = 0; j < 5 && !overflow_mult; j++) {
            try { evaluator.multiply_inplace(attacked_mult, attack_value); } catch (...) { overflow_mult = true; break; }
        }
        Plaintext dec_attack_mult;
        string status = "OK";
        uint64_t curr_val = 0;
        int curr_noise = 0;
        try { curr_noise = decryptor.invariant_noise_budget(attacked_mult); } catch (...) { curr_noise = 0; }
        try {
            decryptor.decrypt(attacked_mult, dec_attack_mult);
            curr_val = dec_attack_mult[0];
            if (curr_val != expected_mult) { status = "CORRUPTED"; overflow_mult = true; }
            else if (curr_noise < mult_threshold) { status = "DANGER"; overflow_mult = true; }
        } catch (...) { status = "ERROR"; curr_val = 0; overflow_mult = true; }
        print_operation_status("Mult Attack #" + to_string(i), curr_val, expected_mult, curr_noise, mult_noise, status);
        if (overflow_mult) break;
    }

    // --- Simulated Attack: Addition ---
    cout << "\nPhase 2: Attack Simulation (Addition)" << endl;
    cout << string(100, '-') << endl;
    Ciphertext attacked_add = add_result;
    uint64_t expected_add = add_value;
    bool overflow_add = false;
    for (int i = 1; i <= 100; i += 5) {
        for (int j = 0; j < 5 && !overflow_add; j++) {
            try { evaluator.add_inplace(attacked_add, encrypted2); } catch (...) { overflow_add = true; break; }
        }
        Plaintext dec_attack_add;
        string status = "OK";
        uint64_t curr_val = 0;
        int curr_noise = 0;
        try { curr_noise = decryptor.invariant_noise_budget(attacked_add); } catch (...) { curr_noise = 0; }
        try {
            decryptor.decrypt(attacked_add, dec_attack_add);
            curr_val = dec_attack_add[0];
            if (curr_val != expected_add + (i * value2)) { status = "CORRUPTED"; overflow_add = true; }
            else if (curr_noise < add_threshold) { status = "DANGER"; overflow_add = true; }
        } catch (...) { status = "ERROR"; curr_val = 0; overflow_add = true; }
        print_operation_status("Add Attack #" + to_string(i), curr_val, expected_add + (i * value2), curr_noise, add_noise, status);
        if (overflow_add) break;
    }

    // --- Simulated Attack: Subtraction ---
    cout << "\nPhase 2: Attack Simulation (Subtraction)" << endl;
    cout << string(100, '-') << endl;
    Ciphertext attacked_sub = sub_result;
    uint64_t expected_sub = sub_value;
    bool overflow_sub = false;
    for (int i = 1; i <= 100; i += 5) {
        for (int j = 0; j < 5 && !overflow_sub; j++) {
            try { evaluator.sub_inplace(attacked_sub, encrypted2); } catch (...) { overflow_sub = true; break; }
        }
        Plaintext dec_attack_sub;
        string status = "OK";
        uint64_t curr_val = 0;
        int curr_noise = 0;
        try { curr_noise = decryptor.invariant_noise_budget(attacked_sub); } catch (...) { curr_noise = 0; }
        try {
            decryptor.decrypt(attacked_sub, dec_attack_sub);
            curr_val = dec_attack_sub[0];
            if (curr_val != expected_sub - (i * value2)) { status = "CORRUPTED"; overflow_sub = true; }
            else if (curr_noise < sub_threshold) { status = "DANGER"; overflow_sub = true; }
        } catch (...) { status = "ERROR"; curr_val = 0; overflow_sub = true; }
        print_operation_status("Sub Attack #" + to_string(i), curr_val, expected_sub - (i * value2), curr_noise, sub_noise, status);
        if (overflow_sub) break;
    }
    
    cout << "\nNoise Budget Analysis:" << endl;
    cout << "1. Initial noise budget: " << initial_noise << " bits" << endl;
    cout << "2. Legitimate operation (100×10) noise budget: " << initial_noise << " bits" << endl;
    cout << "3. Tight noise threshold for overflow: " << static_cast<int>(initial_noise * 0.33) << " bits (33% of legitimate)" << endl;
    cout << "4. Attack simulates noise growth without changing value (multiply by 1)" << endl;
    cout << "5. Overflow/corruption detected if value is wrong or noise drops below threshold" << endl;
    
    return 0;
} 