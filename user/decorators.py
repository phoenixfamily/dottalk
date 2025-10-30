from functools import wraps
from django.http import JsonResponse
from django.contrib.auth import get_user_model

User = get_user_model()

def require_auth_token(view_func):
    """
    دکوریتور برای viewهای معمولی Django
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith("Token "):
            return JsonResponse({'detail': 'توکن یافت نشد یا فرمت نادرست است'}, status=401)

        token = auth_header.split(" ")[1]
        try:
            user = User.objects.get(auth_token=token, is_active=True)
        except User.DoesNotExist:
            return JsonResponse({'detail': 'توکن نامعتبر است'}, status=401)

        request.user = user
        return view_func(request, *args, **kwargs)

    return wrapper
