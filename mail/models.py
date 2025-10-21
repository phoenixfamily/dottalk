from django.db import models
from django.conf import settings


class EmailAccount(models.Model):
    """
    External or local mailbox used by DotTalk for sending/receiving.
    For local mailboxes (on DotTalk-managed domains), provider='local'
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="email_accounts")
    email = models.EmailField(unique=True)
    provider = models.CharField(max_length=50, default="custom")  # e.g. gmail, yahoo, outlook, local
    display_name = models.CharField(max_length=255, blank=True, null=True)

    # connection settings (for IMAP/SMTP sync). These should be encrypted at rest.
    imap_host = models.CharField(max_length=255, blank=True, null=True)
    imap_port = models.PositiveIntegerField(default=993)
    smtp_host = models.CharField(max_length=255, blank=True, null=True)
    smtp_port = models.PositiveIntegerField(default=587)
    use_ssl = models.BooleanField(default=True)

    username = models.CharField(max_length=255, blank=True, null=True)
    password_encrypted = models.TextField(blank=True, null=True)  # encrypt with lib/vault

    is_enabled = models.BooleanField(default=True)
    last_synced = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # for local mailboxes hosted on DotTalk this points to Mailbox model (optional)
    # mailbox = models.OneToOneField('LocalMailbox', null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        indexes = [
            models.Index(fields=["user", "email"]),
        ]

    def __str__(self):
        return self.email
