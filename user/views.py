import json
import base64
import secrets
from dataclasses import asdict

from django.shortcuts import render
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from django.core.cache import cache
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from webauthn.helpers.structs import RegistrationCredential, AuthenticatorAttestationResponse
from user.models import User
from .models import WebAuthnCredential
from .webauthn_utils import (
    generate_registration_challenge,
    verify_registration_response_data,
    generate_authentication_challenge,
    verify_authentication_response_data,
)


@api_view(["POST"])
@permission_classes([AllowAny])
def webauthn_register_options(request):
    user = request.user if request.user.is_authenticated else User.objects.create_user(
        username=f"dt-{secrets.token_urlsafe(6)}"
    )

    opts = generate_registration_challenge(user)
    cache.set(f"register_challenge_{user.id}", opts.challenge, timeout=600)

    opts_dict = asdict(opts)

    # تبدیل تمام bytes به base64 string برای سازگاری با JSON
    def encode_bytes(obj):
        if isinstance(obj, (bytes, bytearray)):
            return base64.urlsafe_b64encode(obj).rstrip(b"=").decode("utf-8")
        elif isinstance(obj, list):
            return [encode_bytes(i) for i in obj]
        elif isinstance(obj, dict):
            return {k: encode_bytes(v) for k, v in obj.items()}
        return obj

    opts_json_ready = encode_bytes(opts_dict)

    return Response(opts_json_ready)


def b64decode(data: str) -> bytes:
    """Decode base64 or base64url safely"""
    data = data.replace("-", "+").replace("_", "/")
    padding = "=" * (-len(data) % 4)
    return base64.b64decode(data + padding)


@api_view(["POST"])
@permission_classes([AllowAny])
def webauthn_register_verify(request):
    """Verify WebAuthn registration"""
    user = request.user if request.user.is_authenticated else None
    if not user:
        return Response({"error": "User not authenticated"}, status=400)

    challenge = cache.get(f"register_challenge_{user.id}")
    if not challenge:
        return Response({"error": "Challenge expired or not found"}, status=400)

    data = request.data
    try:
        # ساخت response درست
        response = AuthenticatorAttestationResponse(
            client_data_json=b64decode(data["response"]["clientDataJSON"]),
            attestation_object=b64decode(data["response"]["attestationObject"]),
        )

        # ساخت credential نهایی
        credential = RegistrationCredential(
            id=data["id"],
            raw_id=b64decode(data["rawId"]),
            response=response,
            type=data["type"],
        )

        verification = verify_registration_response_data(
            user=user,
            data=data,  # raw JSON داده‌ای که از فرانت میاد
            expected_challenge=challenge,
        )

        WebAuthnCredential.objects.create(
            user=user,
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
        )

        return Response({"success": True})

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

# ---- ورود با Passkey ----

@api_view(["POST"])
@permission_classes([AllowAny])
def webauthn_login_options(request):
    """ارسال challenge برای ورود"""
    username = request.data.get("username")
    user = get_object_or_404(User, username=username)
    creds = user.webauthn_credentials.all()
    opts = generate_authentication_challenge(creds)
    cache.set(f"auth_challenge_{user.id}", opts.challenge, timeout=600)
    return Response(opts.model_dump_json())


@api_view(["POST"])
@permission_classes([AllowAny])
def webauthn_login_verify(request):
    """بررسی پاسخ ورود"""
    username = request.data.get("username")
    data = json.dumps(request.data)
    user = get_object_or_404(User, username=username)
    challenge = cache.get(f"auth_challenge_{user.id}")

    cred_id = request.data.get("id")
    credential = get_object_or_404(WebAuthnCredential, user=user, credential_id=cred_id)

    verification = verify_authentication_response_data(data, challenge, credential)

    credential.sign_count = verification.new_sign_count
    credential.save()

    # اینجا session یا JWT صادر کن
    return Response({"status": "authenticated", "user": user.username})



def dashboard_view(request):
    return render(request, 'dashboard.html')
