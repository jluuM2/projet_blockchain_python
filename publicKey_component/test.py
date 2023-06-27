import pytest
import hashlib
import binascii
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import public_key as ecdsa

def test_recover_pub_key_ecdsa_valid():
    # Generate private key
    private_key = ec.generate_private_key(ec.SECP256K1())
    # Extract public key
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    # Convert public key to hex string representation
    expected_public_key = binascii.hexlify(public_key_bytes).decode()
    # Create a message to sign
    message = "Hello, World!"
    # Sign the message
    signature = private_key.sign(message.encode(), ec.ECDSA(hashes.SHA256()))
    # Convert the signature to hex string representation
    r, s = decode_dss_signature(signature)
    signature_hex = '%064x%064x' % (r, s)
    # Test recover_pub_key_ecdsa
    assert ecdsa.recover_pub_key_ecdsa(signature_hex, message) == expected_public_key

def test_recover_pub_key_ecdsa_invalid_signature():
    signature = "3046022100b12fe1c052a85e3a7356163ca9d12942f5f9f9e3b78f556aad2bb90a07f0aaf402202e6a6f1aaa1d3418f602dadc9b66a34a24e8ed7e620c378f57cbb8617894e632"
    message = "Hello, World!"
    with pytest.raises(RuntimeError):
        ecdsa.recover_public_key(signature, message)

def test_recover_pub_key_ecdsa_wrong_signature_type():
    signature = 123
    message = "Hello, World!"
    with pytest.raises(TypeError):
        ecdsa.recover_public_key(signature, message)

def test_recover_pub_key_ecdsa_wrong_message_type():
    signature = "3045022100c12fe1c052a85e3a7356163ca9d12942f5f9f9e3b78f556aad2bb90a07f0aaf402202e6a6f1aaa1d3418f602dadc9b66a34a24e8ed7e620c378f57cbb8617894e632"
    message = 123
    with pytest.raises(TypeError):
        ecdsa.recover_public_key(signature, message)
