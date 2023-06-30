#include <stdexcept>
#include <string>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <pybind11/pybind11.h>

/**
 * Recovers a public key from a signed message using ECDSA.
 * @param signature: The signature of the signed message.
 * @param message: The original message.
 * @returns: The recovered public key.
 * @throws std::runtime_error: If the recovery of the public key fails.
 */
#include "uECC.h"
#include <stdio.h>
#include <stdexcept>
#include <string>

std::string recover_public_key(const std::string& signature_hex, const std::string& message_hex) {
    // Verify that the signature and message are in hexadecimal format
    if (signature_hex.empty() || signature_hex.substr(0, 2) != "0x" ||
        message_hex.empty() || message_hex.substr(0, 2) != "0x") {
        throw std::invalid_argument("The signature and message must be in hexadecimal format (e.g., '0x1a2b3c...', '0x4d657373616765')");
    }

    // Convert the signature and message from hexadecimal to binary
    size_t signature_size = (signature_hex.size() - 2) / 2;
    size_t message_size = (message_hex.size() - 2) / 2;
    uint8_t signature[uECC_BYTES * 2];
    uint8_t message[uECC_BYTES * 2];
    for (size_t i = 0; i < signature_size; ++i) {
        std::string byte_string = signature_hex.substr(i * 2 + 2, 2);
        signature[i] = static_cast<uint8_t>(std::stoi(byte_string, nullptr, 16));
    }
    for (size_t i = 0; i < message_size; ++i) {
        std::string byte_string = message_hex.substr(i * 2 + 2, 2);
        message[i] = static_cast<uint8_t>(std::stoi(byte_string, nullptr, 16));
    }

    // Iterate through possible public keys and verify the signature
    std::string public_key_hex;
    for (size_t i = 0; i < uECC_CURVE_COUNT; ++i) {
        const struct uECC_Curve_t* curve = uECC_get_curve_by_index(i);
        uint8_t public_key[uECC_BYTES * 2];
        
        // Compute the public key for the current curve
        if (!uECC_compute_public_key(signature, message, message_size, public_key, curve)) {
            continue; // Invalid public key for this curve, try the next one
        }

        // Verify if the computed public key produces the given signature
        if (uECC_verify(public_key, message, message_size, signature, curve)) {
            // Convert the public key from binary to hexadecimal
            public_key_hex.clear();
            for (size_t j = 0; j < uECC_BYTES * 2; ++j) {
                char byte_string[3];
                sprintf(byte_string, "%02x", public_key[j]);
                public_key_hex += byte_string;
            }
            break; // Found a valid public key, exit the loop
        }
    }

    if (public_key_hex.empty()) {
        throw std::runtime_error("Failed to recover public key");
    }

    return public_key_hex;
}


/**
 * Pybind11 module definition.
 * The module is named "public_key" and exposes the function recover_public_key to Python.
 */
PYBIND11_MODULE(public_key, m) {
    m.doc() = "ECDSA Public Key Recovery module";
    m.def("recover_public_key", &recover_public_key, "Recover ECDSA public key from signature and message");
}
