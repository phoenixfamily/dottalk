import json
import base64
import secrets
from dataclasses import asdict
from datetime import timedelta

from django.conf import settings
import random

from django.contrib.auth import login
from django.utils import timezone
from django_user_agents.utils import get_user_agent
from django.shortcuts import render
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from django.core.cache import cache
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import AccessToken
from webauthn import verify_registration_response
from webauthn.helpers.structs import RegistrationCredential, AuthenticatorAttestationResponse

from DotTalk import settings
from user.models import User, UserDeviceInfo, DeviceAccessToken
from .decorators import require_auth_token
from .models import WebAuthnCredential
from .webauthn_utils import (
    generate_registration_challenge,
    generate_authentication_challenge,
    verify_authentication_response_data,
)

DEVICE_TOKEN_EXPIRY_DAYS = 30  # مدت اعتبار ورود بدون auth_token


@api_view(["GET"])
@permission_classes([AllowAny])
def custom_captcha(request):
    a, b = random.randint(1, 9), random.randint(1, 9)
    question = f"{a} + {b} = ?"
    answer = str(a + b)
    # ذخیره در session (یا cache)
    request.session["captcha_answer"] = answer
    return Response({"question": question})


@api_view(["POST"])
@permission_classes([AllowAny])
def webauthn_register_options(request):
    captcha_response = request.data.get("captcha")
    if not captcha_response or captcha_response != request.session.get("captcha_answer"):
        return Response({"error": "Captcha not valid"}, status=400)

    # ایجاد کاربر موقت
    user = User.objects.create_user(username=f"dt-{secrets.token_urlsafe(6)}")

    # ایجاد JWT موقت برای verify
    temp_token = AccessToken.for_user(user)
    temp_token['webauthn'] = True  # optional flag

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

    return Response({
        "webauthn_options": opts_json_ready,
        "temp_token": str(temp_token),
    })


def verify_captcha(request, user_answer: str) -> bool:
    correct = request.session.get("captcha_answer")
    if not correct:
        return False
    return user_answer.strip() == correct


def b64decode(data: str) -> bytes:
    """Decode base64 or base64url safely"""
    data = data.replace("-", "+").replace("_", "/")
    padding = "=" * (-len(data) % 4)
    return base64.b64decode(data + padding)


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR', 'Unknown')
    return ip


@api_view(["POST"])
@permission_classes([AllowAny])
def webauthn_register_verify(request):
    user_agent = get_user_agent(request)
    ip_address = get_client_ip(request)

    # دریافت JWT از body
    temp_token_str = request.data.get("temp_token")
    if not temp_token_str:
        return Response({"error": "Missing temporary token"}, status=400)

    try:
        validated_token = JWTAuthentication().get_validated_token(temp_token_str)
        user = JWTAuthentication().get_user(validated_token)
    except Exception:
        return Response({"error": "Invalid token"}, status=400)


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

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=settings.WEBAUTHN_ORIGIN,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
        )

        device_info = UserDeviceInfo.objects.create(
            user=user,
            device_type='Mobile' if user_agent.is_mobile else 'Tablet' if user_agent.is_tablet else 'Desktop' if user_agent.is_pc else 'Unknown',
            device_model=user_agent.device.family,
            browser=user_agent.browser.family,
            operating_system=user_agent.os.family,
            os_version=user_agent.os.version_string,
            ip_address=ip_address
        )

        WebAuthnCredential.objects.create(
            user=user,
            device=device_info,
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
        )

        device_token = DeviceAccessToken.objects.create(
            user=user,
            device=device_info,
            token=secrets.token_urlsafe(32),
            expires_at=timezone.now() + timedelta(days=DEVICE_TOKEN_EXPIRY_DAYS)
        )

        return Response({
            "success": True,
            "message": "اکانت شما با موفقیت ساخته شد",
            "auth_token": user.auth_token,  # یا token مربوط به device
            "device_info": {
                'ip_address': device_token.device.ip_address,
                'device_model': device_token.device.device_model,
                "device_type": device_token.device.device_type,
                "browser": device_token.device.browser,
                "os": device_token.device.operating_system,
            },
        })


    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# --- 1️⃣ ساخت Challenge با credential_id ---
@api_view(["POST"])
@permission_classes([AllowAny])
def webauthn_login_options(request):
    """
    ✅ ارسال challenge برای ورود بر اساس credential_id
    """
    credential_id = request.data.get("credential_id")
    if not credential_id:
        return Response({"error": "credential_id لازم است"}, status=400)

    credential = get_object_or_404(WebAuthnCredential, credential_id=credential_id)
    user = credential.user

    device_token = DeviceAccessToken.objects.filter(
        user=user,
        device=credential.device
    ).order_by("-created_at").first()

    if not device_token or not device_token.is_valid():
        return Response({
            "error": "اعتبار دستگاه منقضی شده است",
            "requires_token": True,
            "message": "لطفاً با auth_token وارد شوید تا Passkey جدید ثبت شود."
        }, status=401)

    opts = generate_authentication_challenge([credential])
    cache.set(f"auth_challenge_{credential_id}", opts.challenge, timeout=600)

    # Base64URL encode for JS
    def encode_bytes(obj):
        if isinstance(obj, (bytes, bytearray)):
            return base64.urlsafe_b64encode(obj).rstrip(b"=").decode("utf-8")
        elif isinstance(obj, list):
            return [encode_bytes(i) for i in obj]
        elif isinstance(obj, dict):
            return {k: encode_bytes(v) for k, v in obj.items()}
        return obj

    return Response(encode_bytes(asdict(opts)))


# --- 2️⃣ بررسی پاسخ WebAuthn ---
@api_view(["POST"])
@permission_classes([AllowAny])
def webauthn_login_verify(request):
    """
    ✅ بررسی پاسخ WebAuthn و لاگین کاربر
    ✅ صدور یا تأیید auth_token
    ✅ ثبت زمان و IP
    """
    credential_id = request.data.get("id")
    if not credential_id:
        return Response({"error": "شناسه credential یافت نشد"}, status=400)

    credential = get_object_or_404(WebAuthnCredential, credential_id=credential_id)
    user = credential.user
    challenge = cache.get(f"auth_challenge_{credential_id}")

    if not challenge:
        return Response({"error": "Challenge منقضی یا یافت نشد"}, status=400)

    device_token = DeviceAccessToken.objects.filter(
        user=user,
        device=credential.device
    ).order_by("-created_at").first()

    if not device_token or not device_token.is_valid():
        return Response({
            "error": "اعتبار دستگاه منقضی شده است",
            "requires_token": True,
            "message": "لطفاً با auth_token وارد شوید تا Passkey جدید ثبت شود."
        }, status=401)

    try:
        verification = verify_authentication_response_data(
            json.dumps(request.data), challenge, credential
        )

        # به‌روزرسانی شمارنده امنیتی
        credential.sign_count = verification.new_sign_count
        credential.save()

        # اگر لاگین نیست، لاگینش کن
        if not request.user.is_authenticated:
            login(request, user)

        # ثبت زمان و IP
        user.last_login_at = timezone.now()
        user.last_ip = get_client_ip(request)
        user.save(update_fields=["last_login_at", "last_ip"])

        device_token.expires_at = timezone.now() + timedelta(days=DEVICE_TOKEN_EXPIRY_DAYS)
        device_token.save(update_fields=["expires_at"])

        return Response({
            "status": "authenticated",
            "message": "ورود موفقیت‌آمیز بود ✅",
            "username": user.username,
            "auth_token": user.auth_token,
            "last_login_at": user.last_login_at,
            "ip": user.last_ip,
        })

    except Exception as e:
        return Response({"error": str(e)}, status=400)


@api_view(["POST"])
@permission_classes([AllowAny])
def token_login(request):
    """
    ✅ ورود با auth_token زمانی که Passkey معتبر نیست
    ✅ صدور یا تمدید Device Token خودکار
    """
    token = request.data.get("auth_token")
    if not token:
        return Response({"error": "توکن ارسالی وجود ندارد"}, status=400)

    try:
        user = User.objects.get(auth_token=token, is_active=True)
    except User.DoesNotExist:
        return Response({"error": "توکن نامعتبر است"}, status=400)

    login(request, user)
    user.last_login_at = timezone.now()
    user.last_ip = get_client_ip(request)
    user.save(update_fields=["last_login_at", "last_ip"])

    # 🔄 Device Token خودکار برای دستگاه جدید یا موجود
    user_agent = get_user_agent(request)
    device_info, _ = UserDeviceInfo.objects.get_or_create(
        user=user,
        device_type='Mobile' if user_agent.is_mobile else 'Tablet' if user_agent.is_tablet else 'Desktop' if user_agent.is_pc else 'Unknown',
        device_model=user_agent.device.family,
        browser=user_agent.browser.family,
        operating_system=user_agent.os.family,
        defaults={"ip_address": user.last_ip}
    )

    device_token, created = DeviceAccessToken.objects.get_or_create(
        user=user,
        device=device_info,
        defaults={"token": secrets.token_urlsafe(32),
                  "expires_at": timezone.now() + timedelta(days=DEVICE_TOKEN_EXPIRY_DAYS)}
    )

    # اگر Token قبلاً بود، تمدیدش کن
    if not created:
        device_token.expires_at = timezone.now() + timedelta(days=DEVICE_TOKEN_EXPIRY_DAYS)
        device_token.save(update_fields=["expires_at"])

    return Response({
        "success": True,
        "message": "ورود با توکن موفقیت‌آمیز بود ✅",
        "username": user.username,
        "auth_token": user.auth_token,
        "device_token": device_token.token,
        "device_token_expires_at": device_token.expires_at,
        "can_register_new_device": True
    })



@require_auth_token
def dashboard_view(request):
    return render(request, 'dashboard.html')


def register_view(request):
    return render(request, 'register.html')


def login_view(request):
    return render(request, 'login.html')
