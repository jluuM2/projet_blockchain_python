import ecdsa
from ecdsa.util import sigdecode_string
import base64
import json

class PublicKeyRecoveryComponent:
    def __init__(self, curve):
        self.curve = curve

    def take_signature(self, json_string):
        data = json.loads(json_string)
        if 'signature' not in data:
            raise ValueError("JSON does not contain 'signature' key")
        signature_base64 = data['signature']
        try:
            self.signature = base64.b64decode(signature_base64)
        except base64.binascii.Error:
            raise ValueError("Signature is not base64 encoded")

    def validate_signature_format(self):
        # Here you can implement the logic to validate the format of the signature.
        # This is a simple example, you might need to adjust it according to your specific requirements.
        try:
            r, s = sigdecode_string(self.signature, self.curve.order)
            return True
        except:
            return False

    def recover_public_key(self, message):
        try:
            # This function can raise a "BadSignatureError" if the signature doesn't match
            public_key = ecdsa.VerifyingKey.from_public_key_recovery(
                self.signature, message, self.curve, hashfunc=ecdsa.util.sha256)
            
            # If we got here, the signature matched, so return the public key
            return public_key
        except ecdsa.keys.BadSignatureError:
            # The signature didn't match
            raise ValueError("Invalid signature")
