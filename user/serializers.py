from rest_framework import serializers
import base64

def b64encode_bytes(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

def b64decode_bytes(data: str) -> bytes:
    data = data.replace("-", "+").replace("_", "/")
    padding = "=" * (-len(data) % 4)
    return base64.b64decode(data + padding)

class WebAuthnRegistrationOptionsSerializer(serializers.Serializer):
    rp = serializers.DictField()
    user = serializers.DictField()
    challenge = serializers.CharField()
    pub_key_cred_params = serializers.ListField()
    timeout = serializers.IntegerField()
    exclude_credentials = serializers.ListField()
    authenticator_selection = serializers.DictField(allow_null=True)
    attestation = serializers.CharField()
