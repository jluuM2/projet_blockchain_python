import pytest
import public_key as ecdsa_recovery

def test_recover_public_key_valid():
    signature = "3044022042b204d01b9e14f84b3565f0801a46a8d6be7697c04a0b442e555d27b5a8b75d02203742e343d68c2f01cdeacdc95cfd4b167413a40571f2f00c9f61ff93dd2452a5"
    message = "Hello, World!"
    expected_public_key = "047db68d9c45390daa255acd2e9ea05a48e5c9328644d5263d2da83669b717d30436b526ed9e53280b8a0711768a37c848c5beaa6fe0ef9f51e94d5c0c4485b628"
    assert ecdsa_recovery.recover_public_key(signature, message) == expected_public_key

def test_recover_public_key_invalid_signature():
    signature = "invalid_signature"
    message = "Hello, World!"
    with pytest.raises(ValueError):
        ecdsa_recovery.recover_public_key(signature, message)

def test_recover_public_key_wrong_message_type():
    signature = "3044022042b204d01b9e14f84b3565f0801a46a8d6be7697c04a0b442e555d27b5a8b75d02203742e343d68c2f01cdeacdc95cfd4b167413a40571f2f00c9f61ff93dd2452a5"
    message = 123
    with pytest.raises(TypeError):
        ecdsa_recovery.recover_public_key(signature, message)

def test_recover_public_key_empty_signature():
    signature = ""
    message = "Hello, World!"
    with pytest.raises(ValueError):
        ecdsa_recovery.recover_public_key(signature, message)

if __name__ == "__main__":
    pytest.main()
