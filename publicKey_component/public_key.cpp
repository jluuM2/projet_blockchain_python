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
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) {
        throw std::runtime_error("Failed to create EC_GROUP");
    }

    EC_KEY* eckey = EC_KEY_new();
    if (!eckey) {
        EC_GROUP_free(group);
        throw std::runtime_error("Failed to create EC_KEY");
    }

    if (EC_KEY_set_group(eckey, group) != 1) {
        EC_KEY_free(eckey);
        EC_GROUP_free(group);
        throw std::runtime_error("Failed to set EC_GROUP for EC_KEY");
    }

    BIGNUM* r = BN_new();
    if (!r) {
        EC_KEY_free(eckey);
        EC_GROUP_free(group);
        throw std::runtime_error("Failed to create BIGNUM for r");
    }

    BIGNUM* s = BN_new();
    if (!s) {
        BN_free(r);
        EC_KEY_free(eckey);
        EC_GROUP_free(group);
        throw std::runtime_error("Failed to create BIGNUM for s");
    }

    if (BN_hex2bn(&r, signature.c_str()) == 0 || BN_hex2bn(&s, signature.c_str() + 64) == 0) {
        BN_free(s);
        BN_free(r);
        EC_KEY_free(eckey);
        EC_GROUP_free(group);
        throw std::runtime_error("Failed to convert signature to BIGNUMs");
    }

    ECDSA_SIG* ecdsa_sig = ECDSA_SIG_new();
    if (!ecdsa_sig) {
        BN_free(s);
        BN_free(r);
        EC_KEY_free(eckey);
        EC_GROUP_free(group);
        throw std::runtime_error("Failed to create ECDSA_SIG");
    }

    ECDSA_SIG_set0(ecdsa_sig, r, s);

    if (ECDSA_do_recover_key(eckey, ecdsa_sig) != 1) {
        ECDSA_SIG_free(ecdsa_sig);
        BN_free(s);
        BN_free(r);
        EC_KEY_free(eckey);
        EC_GROUP_free(group);
        throw std::runtime_error("Failed to recover ECDSA public key");
    }

    const EC_POINT* pubkey_point = EC_KEY_get0_public_key(eckey);
    if (!pubkey_point) {
        ECDSA_SIG_free(ecdsa_sig);
        BN_free(s);
        BN_free(r);
        EC_KEY_free(eckey);
        EC_GROUP_free(group);
        throw std::runtime_error("Failed to retrieve ECDSA public key point");
    }

    std::string public_key_hex;
    EC_POINT_point2hex(group, pubkey_point, POINT_CONVERSION_UNCOMPRESSED, &public_key_hex, nullptr);
    
    ECDSA_SIG_free(ecdsa_sig);
    BN_free(s);
    BN_free(r);
    EC_KEY_free(eckey);
    EC_GROUP_free(group);

    return public_key_hex;
}

/**
 * Pybind11 module definition.
 * The module is named "ecdsa_publickey_recovery" and exposes the function recover_public_key to Python.
 */
PYBIND11_MODULE(ecdsa_publickey_recovery, m) {
    m.doc() = "ECDSA Public Key Recovery module";
    m.def("recover_public_key", &recover_public_key, "Recover ECDSA public key from signature and message");
}
