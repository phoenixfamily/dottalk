from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser

User = get_user_model()

class AuthTokenMiddleware(MiddlewareMixin):
    """
    شناسایی خودکار کاربر از طریق هدر Authorization (Token <auth_token>)
    برای همه‌ی requestها (چه API و چه HTML)
    """
    def process_request(self, request):
        # اگر قبلاً با سشن وارد شده باشه، نیازی به بررسی مجدد نیست
        if request.user.is_authenticated:
            return

        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Token '):
            request.user = AnonymousUser()
            return

        token = auth_header.split(' ')[1]

        try:
            user = User.objects.get(auth_token=token, is_active=True)
            request.user = user
        except User.DoesNotExist:
            request.user = AnonymousUser()
