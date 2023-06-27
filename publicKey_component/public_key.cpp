#include <string>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
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
    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (eckey == nullptr) {
        throw std::runtime_error("Failed to create EC_KEY");
    }

    const unsigned char* signature_data = reinterpret_cast<const unsigned char*>(signature.c_str());
    ECDSA_SIG* ecdsa_sig = ECDSA_SIG_new();
    if (ecdsa_sig == nullptr) {
        EC_KEY_free(eckey);
        throw std::runtime_error("Failed to create ECDSA_SIG");
    }

    BIGNUM* r = BN_new();
    BIGNUM* s = BN_new();
    if (r == nullptr || s == nullptr) {
        ECDSA_SIG_free(ecdsa_sig);
        EC_KEY_free(eckey);
        throw std::runtime_error("Failed to create BIGNUM");
    }

 if (BN_hex2bn(&r, reinterpret_cast<const char*>(signature_data)) == 0 ||
    BN_hex2bn(&s, reinterpret_cast<const char*>(signature_data + 64)) == 0) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(ecdsa_sig);
        EC_KEY_free(eckey);
        throw std::runtime_error("Failed to parse signature components");
    }

    ECDSA_SIG_set0(ecdsa_sig, r, s);

    if (EC_KEY_recover_key(eckey, ecdsa_sig, reinterpret_cast<const unsigned char*>(message.c_str()), message.size()) != 1) {
        ECDSA_SIG_free(ecdsa_sig);
        EC_KEY_free(eckey);
        throw std::runtime_error("Failed to recover public key");
    }

    ECDSA_SIG_free(ecdsa_sig);

    const EC_POINT* point = EC_KEY_get0_public_key(eckey);
    if (point == nullptr) {
        EC_KEY_free(eckey);
        throw std::runtime_error("Failed to get EC_POINT from EC_KEY");
    }

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (group == nullptr) {
        EC_KEY_free(eckey);
        throw std::runtime_error("Failed to create EC_GROUP");
    }

    size_t point_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    if (point_len == 0) {
        EC_KEY_free(eckey);
        EC_GROUP_free(group);
        throw std::runtime_error("Failed to compute point length");
    }

    std::string public_key(point_len, '\0');
    unsigned char* public_key_data = reinterpret_cast<unsigned char*>(&public_key[0]);
    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, public_key_data, point_len, nullptr) != point_len) {
        EC_KEY_free(eckey);
        EC_GROUP_free(group);
        throw std::runtime_error("Failed to convert point to octet string");
    }

    EC_KEY_free(eckey);
    EC_GROUP_free(group);

    return public_key;
}

/**
 * Pybind11 module definition.
 * The module is named "ecdsa_publickey_recovery" and exposes the function recover_public_key to Python.
 */
PYBIND11_MODULE(ecdsa_publickey_recovery, m) {
    m.doc() = "ECDSA Public Key Recovery module";
    m.def("recover_public_key", &recover_public_key, "Recover ECDSA public key from signature and message");
}
