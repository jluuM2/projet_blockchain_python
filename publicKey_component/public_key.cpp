#include <string>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <pybind11/pybind11.h>

namespace py = pybind11;

/**
 * Recovers the public key from an ECDSA signature and message.
 * @param signature: The ECDSA signature as a hexadecimal string.
 * @param message: The message used to generate the signature.
 * @returns: The recovered public key as a hexadecimal string.
 * @throws std::runtime_error: If the recovery process fails.
 */
std::string recover_public_key(const std::string& signature, const std::string& message) {
    const char* signature_data = signature.c_str();
    const char* message_data = message.c_str();

    // Create an EC_GROUP object for the secp256k1 curve
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (group == nullptr) {
        throw std::runtime_error("Failed to create EC_GROUP");
    }

    // Create an EC_KEY object
    EC_KEY* eckey = EC_KEY_new();
    if (eckey == nullptr) {
        EC_GROUP_free(group);
        throw std::runtime_error("Failed to create EC_KEY");
    }

    // Set the EC_GROUP for the EC_KEY
    if (EC_KEY_set_group(eckey, group) != 1) {
        EC_GROUP_free(group);
        EC_KEY_free(eckey);
        throw std::runtime_error("Failed to set EC_GROUP for EC_KEY");
    }

    // Convert the signature to BIGNUMs
    BIGNUM* r = BN_new();
    BIGNUM* s = BN_new();
    if (BN_hex2bn(&r, signature_data) == 0 || BN_hex2bn(&s, signature_data + 64) == 0) {
        EC_GROUP_free(group);
        EC_KEY_free(eckey);
        BN_free(r);
        BN_free(s);
        throw std::runtime_error("Failed to convert signature to BIGNUMs");
    }

    // Create an ECDSA_SIG object
    ECDSA_SIG* ecdsa_sig = ECDSA_SIG_new();
    if (ecdsa_sig == nullptr) {
        EC_GROUP_free(group);
        EC_KEY_free(eckey);
        BN_free(r);
        BN_free(s);
        throw std::runtime_error("Failed to create ECDSA_SIG");
    }

    // Set the r and s values of the ECDSA_SIG
    ECDSA_SIG_set0(ecdsa_sig, r, s);

    // Recover the public key from the ECDSA signature
    if (ECDSA_do_verify(reinterpret_cast<const unsigned char*>(message_data), message.size(), ecdsa_sig, eckey) != 1) {
        EC_GROUP_free(group);
        EC_KEY_free(eckey);
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(ecdsa_sig);
        throw std::runtime_error("Failed to recover ECDSA public key");
    }

    // Retrieve the ECDSA public key point
    const EC_POINT* pubkey_point = EC_KEY_get0_public_key(eckey);

    // Convert the ECDSA public key point to a hexadecimal string
    char* public_key_hex = EC_POINT_point2hex(group, pubkey_point, POINT_CONVERSION_UNCOMPRESSED, nullptr);
    if (public_key_hex == nullptr) {
        EC_GROUP_free(group);
        EC_KEY_free(eckey);
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(ecdsa_sig);
        throw std::runtime_error("Failed to retrieve ECDSA public key point");
    }

    std::string public_key(public_key_hex);
    OPENSSL_free(public_key_hex);

    EC_GROUP_free(group);
    EC_KEY_free(eckey);
    BN_free(r);
    BN_free(s);
    ECDSA_SIG_free(ecdsa_sig);

    return public_key;
}

/**
 * Pybind11 module definition.
 * The module is named "ecdsa_publickey_recovery" and exposes the function recover_public_key to Python.
 */
PYBIND11_MODULE(public_key, m) {
    m.doc() = "ECDSA Public Key Recovery module";
    m.def("recover_public_key", &recover_public_key, "Recover ECDSA public key from signature and message");
}
