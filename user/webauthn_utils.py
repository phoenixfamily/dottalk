from django.conf import settings
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    RegistrationCredential,
    AuthenticationCredential,
    AttestationConveyancePreference,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
)

def generate_registration_challenge(user):
    """ایجاد challenge برای ثبت Passkey جدید"""
    return generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        rp_name=settings.WEBAUTHN_RP_NAME,
        user_id=str(user.id).encode(),
        user_name=user.username,
        user_display_name=getattr(user, "display_name", user.username),
        attestation=AttestationConveyancePreference.NONE,
    )


def verify_registration_response_data(user, data, expected_challenge):
    """اعتبارسنجی پاسخ ثبت credential"""
    credential = RegistrationCredential(**data)
    verification = verify_registration_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_origin=settings.WEBAUTHN_ORIGIN,
        expected_rp_id=settings.WEBAUTHN_RP_ID,
    )

    # بعد از موفقیت در verification، credential رو برای کاربر ذخیره می‌کنیم
    from user.models import WebAuthnCredential

    WebAuthnCredential.objects.create(
        user=user,
        credential_id=verification.credential_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
    )

    return verification



def generate_authentication_challenge(credentials):
    """ایجاد challenge برای ورود"""
    allow_credentials = [
        PublicKeyCredentialDescriptor(
            id=c.credential_id,
            type=PublicKeyCredentialType.PUBLIC_KEY,  # ✅ اصلاح‌شده
            transports=c.transports or ["internal"]
        )
        for c in credentials
    ]

    return generate_authentication_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        allow_credentials=allow_credentials,
    )


def verify_authentication_response_data(data, expected_challenge, credential):
    """اعتبارسنجی پاسخ ورود"""
    auth_credential = AuthenticationCredential(**data)
    verification = verify_authentication_response(
        credential=auth_credential,
        expected_challenge=expected_challenge,
        expected_rp_id=settings.WEBAUTHN_RP_ID,
        expected_origin=settings.WEBAUTHN_ORIGIN,
        credential_public_key=credential.public_key,
        credential_current_sign_count=credential.sign_count,
    )
    return verification
