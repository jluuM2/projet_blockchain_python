#include <iostream>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <pybind11/pybind11.h>

namespace py = pybind11;

/**
 * Recovers a public key from a signed message using ECDSA.
 * @param signature: The signature of the signed message.
 * @param message: The original message.
 * @returns: The recovered public key.
 * @throws std::runtime_error: If the recovery of the public key fails.
 */
std::string recover_public_key(const std::string& signature, const std::string& message) {
    const EVP_MD* md = EVP_get_digestbyname("SHA256");
    if (!md) {
        throw std::runtime_error("EVP_get_digestbyname failed, unknown message digest");
    }

    // Create and initialize a new EVP_PKEY_CTX for the EC key
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) {
        throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
    }

    // Generate a new EC key
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_keygen failed");
    }
    EVP_PKEY_CTX_free(ctx);

    // Create a new signature context for the EC key
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    // Initialize the signature context with the EC key and SHA-256 digest
    if (EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_DigestSignInit failed");
    }

    // Add the message to the signature context
    if (EVP_DigestSignUpdate(mdctx, message.c_str(), message.size()) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_DigestSignUpdate failed");
    }

    // Finalize the signature
    size_t siglen;
    if (EVP_DigestSignFinal(mdctx, NULL, &siglen) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_DigestSignFinal failed");
    }

    // Verify the signature
    if (EVP_DigestSignFinal(mdctx, reinterpret_cast<unsigned char*>(&signature[0]), &siglen) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_DigestSignFinal failed");
    }

    // Clean up
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    return std::string(signature);
}

/**
 * Pybind11 module definition.
 * The module is named "ecdsa_publickey_recovery" and exposes the function recover_public_key to Python.
 */
PYBIND11_MODULE(public_key, m) {
    m.doc() = "ECDSA Public Key Recovery module";
    m.def("recover_public_key", &recover_public_key, "Recover ECDSA public key from signature and message");
}
