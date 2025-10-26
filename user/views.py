import json
from django.shortcuts import render
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from django.core.cache import cache
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
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
    # برای کاربر جدید، یوزر خودکار بساز
    user = request.user if request.user.is_authenticated else User.objects.create_user()
    opts = generate_registration_challenge(user)
    cache.set(f"register_challenge_{user.id}", opts.challenge, timeout=600)
    return Response(opts.json())




@api_view(["POST"])
@permission_classes([AllowAny])
def webauthn_register_verify(request):
    """اعتبارسنجی پاسخ ثبت credential"""
    user_id = request.data.get("user_id")
    data = json.dumps(request.data)
    user = get_object_or_404(User, id=user_id)
    challenge = cache.get(f"register_challenge_{user.id}")

    verification = verify_registration_response_data(user, data, challenge)

    credential = WebAuthnCredential.objects.create(
        user=user,
        credential_id=verification.credential_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
    )
    return Response({"status": "ok", "credential_id": credential.credential_id})


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
