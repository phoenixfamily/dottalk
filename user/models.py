# user/models.py
import uuid
import secrets
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils import timezone


def generate_short_username():
    # تولید یک یوزرنیم کوتاه و امن (مثال: dt-8chars)
    return "dt-" + secrets.token_urlsafe(6)


class CustomAccountManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, username, **extra_fields):
        if not username:
            raise ValueError("The given username must be set")
        user = self.model(username=username, **extra_fields)
        user.save(using=self._db)
        return user

    def create_user(self, username=None, **extra_fields):
        if username is None:
            username = generate_short_username()
            while self.model.objects.filter(username=username).exists():
                username = generate_short_username()
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(username, **extra_fields)

    def create_superuser(self, username=None, **extra_fields):
        if username is None:
            username = "admin"
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        return self._create_user(username, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=64, unique=True, default=generate_short_username)
    is_active = models.BooleanField(default=True, verbose_name='فعال')
    created_at = models.DateTimeField(default=timezone.now)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []

    objects = CustomAccountManager()

    def __str__(self):
        return self.username


class WebAuthnCredential(models.Model):
    """
    ذخیره‌ی کلید عمومی و متادیتای وب‌آوتن برای هر user.
    credential_id باید باینری/بیس64 یا hex باشه بسته به پیاده‌سازی.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='webauthn_credentials')
    credential_id = models.CharField(max_length=512, unique=True)
    public_key = models.TextField()
    sign_count = models.BigIntegerField(default=0)
    transports = models.JSONField(blank=True, null=True)  # optional
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"webauthn:{self.user.username}:{self.credential_id[:8]}"


class UserDeviceInfo(models.Model):
    DEVICE_TYPES = [
        ('Mobile', 'Mobile'),
        ('Tablet', 'Tablet'),
        ('Desktop', 'Desktop'),
        ('Unknown', 'Unknown'),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='device_infos', null=True, blank=True)
    device_model = models.CharField(max_length=100, blank=True, null=True)
    device_type = models.CharField(max_length=10, choices=DEVICE_TYPES, default='Unknown')
    operating_system = models.CharField(max_length=50, blank=True, null=True)
    os_version = models.CharField(max_length=50, blank=True, null=True)
    browser = models.CharField(max_length=50, blank=True, null=True)
    browser_version = models.CharField(max_length=50, blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    country = models.CharField(max_length=50, blank=True, null=True)
    city = models.CharField(max_length=50, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.device_type} - {self.device_model or 'Unknown'}"

    class Meta:
        verbose_name = "User Device Info"
        verbose_name_plural = "User Device Infos"


class UserActivityLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='activity_logs', null=True)
    visited_page = models.URLField(blank=True, null=True)
    entry_time = models.DateTimeField(default=timezone.now)
    exit_time = models.DateTimeField(null=True, blank=True)
    clicked_links = models.TextField(null=True, blank=True)
    search_keywords = models.TextField(null=True, blank=True)
    viewed_items = models.TextField(null=True, blank=True)
    error_messages = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def duration_on_page(self):
        if self.exit_time:
            return (self.exit_time - self.entry_time).total_seconds()
        return None

    def __str__(self):
        return f"Activity by {self.user.username if self.user else 'Anonymous'} on {self.visited_page or 'unknown'}"

    class Meta:
        verbose_name = "User Activity Log"
        verbose_name_plural = "User Activity Logs"
