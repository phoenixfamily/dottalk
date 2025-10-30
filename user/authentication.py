from rest_framework import authentication, exceptions
from django.contrib.auth import get_user_model

User = get_user_model()

class AuthTokenAuthentication(authentication.BaseAuthentication):
    """
    احراز هویت کاربران فقط با auth_token
    Header نمونه:
        Authorization: Token <auth_token>
    """
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None  # بدون توکن = بدون احراز، اجازه بدیم Permission کلاس تصمیم بگیره

        parts = auth_header.split()

        if len(parts) != 2 or parts[0].lower() != 'token':
            raise exceptions.AuthenticationFailed('فرمت هدر Authorization معتبر نیست.')

        token = parts[1]

        try:
            user = User.objects.get(auth_token=token, is_active=True)
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed('توکن نامعتبر است.')

        # ذخیره IP و زمان آخرین لاگین
        user.last_ip = request.META.get('REMOTE_ADDR')
        user.last_login_at = user.last_login_at or None
        user.save(update_fields=['last_ip', 'last_login_at'])

        return (user, None)
