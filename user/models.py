import uuid
import secrets
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager


# -------------------------
#  USER MANAGER
# -------------------------
def generate_short_username():
    return "dt-" + secrets.token_urlsafe(6)


class CustomAccountManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, username, **extra_fields):
        if not username:
            raise ValueError("Username must be set")
        user = self.model(username=username, **extra_fields)
        user.save(using=self._db)
        return user

    def create_user(self, username=None, **extra_fields):
        if username is None:
            username = generate_short_username()
            while self.model.objects.filter(username=username).exists():
                username = generate_short_username()
        return self._create_user(username, **extra_fields)

    def create_superuser(self, username=None, **extra_fields):
        username = username or "admin"
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self._create_user(username, **extra_fields)


# -------------------------
#  USER MODEL
# -------------------------
class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=64, unique=True, default=generate_short_username)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)

    # 🔐 توکن شناسایی کلی (برای API و بازیابی)
    auth_token = models.CharField(max_length=128, unique=True, default=lambda: secrets.token_urlsafe(32))

    # آخرین لاگین و IP
    last_login_at = models.DateTimeField(null=True, blank=True)
    last_ip = models.GenericIPAddressField(null=True, blank=True)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []

    objects = CustomAccountManager()

    def __str__(self):
        return self.username


# -------------------------
#  DEVICE INFO
# -------------------------
class UserDeviceInfo(models.Model):
    DEVICE_TYPES = [
        ('Mobile', 'Mobile'),
        ('Tablet', 'Tablet'),
        ('Desktop', 'Desktop'),
        ('Unknown', 'Unknown'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='devices')
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
        return f"{self.user.username} - {self.device_type} ({self.device_model or 'Unknown'})"


# -------------------------
#  DEVICE TOKEN
# -------------------------
class DeviceAccessToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="device_tokens")
    device = models.ForeignKey(UserDeviceInfo, on_delete=models.CASCADE, related_name="tokens")
    token = models.CharField(max_length=128, unique=True, default=lambda: secrets.token_urlsafe(32))
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    def is_valid(self):
        return not self.expires_at or timezone.now() < self.expires_at

    def __str__(self):
        return f"Token for {self.user.username} ({self.device.device_model or 'Unknown'})"


# -------------------------
#  WEBAUTHN CREDENTIAL
# -------------------------
class WebAuthnCredential(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='webauthn_credentials')
    device = models.ForeignKey(UserDeviceInfo, on_delete=models.CASCADE, related_name='webauthn_credentials', null=True, blank=True)
    credential_id = models.CharField(max_length=512, unique=True)
    public_key = models.TextField()
    sign_count = models.BigIntegerField(default=0)
    transports = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.device.device_model if self.device else 'Unknown device'}"


# -------------------------
#  USER ACTIVITY LOG
# -------------------------
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

    def duration_on_page(self):
        return (self.exit_time - self.entry_time).total_seconds() if self.exit_time else None

    def __str__(self):
        return f"{self.user.username if self.user else 'Anon'} - {self.visited_page or 'unknown'}"
