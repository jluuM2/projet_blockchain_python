import ecdsa
from ecdsa.util import sigencode_string
from PublicKeyRecoveryComponent import PublicKeyRecoveryComponent

def test_component():
    # Generate a key pair for testing
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    public_key = private_key.get_verifying_key()

    # Sign a message
    message = b"test message"
    signature = private_key.sign(message, sigencode=sigencode_string)

    # Create a PublicKeyRecoveryComponent instance
    recovery_component = PublicKeyRecoveryComponent(ecdsa.SECP256k1)

    # Test the take_signature method
    recovery_component.take_signature(signature)
    print("take_signature passed")

    # Test the validate_signature_format method
    assert recovery_component.validate_signature_format()
    print("validate_signature_format passed")

    # Test the recover_public_key method
    recovered_public_keys = recovery_component.recover_public_key(message)

    # Check if one of the recovered keys match the original
    assert any(key.to_string() == public_key.to_string() for key in recovered_public_keys)
    print("recover_public_key passed")

    print("All tests passed")

if __name__ == "__main__":
    test_component()
