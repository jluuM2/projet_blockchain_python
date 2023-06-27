import pytest
import public_key as ecdsa

def test_recover_pub_key_ecdsa_valid():
    signature = "3045022100c12fe1c052a85e3a7356163ca9d12942f5f9f9e3b78f556aad2bb90a07f0aaf402202e6a6f1aaa1d3418f602dadc9b66a34a24e8ed7e620c378f57cbb8617894e632"
    message = "Hello, World!"
    expected_public_key = "041ada6aea8d48b3cfd1b1715d0fb478fa451f541027b63ea2c021d96fc27b287c2c5b619793b76ba8fc9a3cd6b80f149659fac6f57340f1e6c5e586e4d6c6edf"
    assert ecdsa.recover_public_key(signature, message) == expected_public_key

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
