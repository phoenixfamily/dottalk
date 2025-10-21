from django.conf import settings
from django.db import models


class Conversation(models.Model):
    """
    A unified conversation that can represent:
    - An internal DotTalk chat
    - A synced Gmail or external email thread
    """
    TYPE_CHOICES = (
        ('internal', 'DotTalk Internal'),
        ('email', 'External Email'),
    )

    type = models.CharField(max_length=10, choices=TYPE_CHOICES, default='internal')
    subject = models.CharField(max_length=255, blank=True, null=True)
    participants = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='dot_conversations')
    thread_id = models.CharField(max_length=255, blank=True, null=True, unique=True)  # Gmail thread ID
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.subject or f"Conversation {self.id}"


class Message(models.Model):
    """
    A message that can exist inside a conversation.
    Works for both email and chat messages.
    """
    conversation = models.ForeignKey(Conversation, related_name='messages', on_delete=models.CASCADE)
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    message_id = models.CharField(max_length=255, blank=True, null=True, unique=True)  # Gmail message ID
    content = models.TextField(blank=True)
    sent_at = models.DateTimeField(auto_now_add=True)

    # --- Tracking fields ---
    delivered_at = models.DateTimeField(blank=True, null=True)  # when message was accepted (SMTP)
    seen_at = models.DateTimeField(blank=True, null=True)       # only works internally in DotTalk
    synced_at = models.DateTimeField(blank=True, null=True)     # when it was synced from Gmail

    # --- Status & meta ---
    is_outgoing = models.BooleanField(default=True)  # True = user sent, False = received
    has_attachments = models.BooleanField(default=False)
    in_reply_to = models.ForeignKey('self', on_delete=models.SET_NULL, blank=True, null=True)
    source = models.CharField(max_length=50, default='dottalk')  # 'gmail', 'outlook', 'dottalk', etc.

    def __str__(self):
        return f"{self.sender} → {self.conversation} ({self.sent_at})"


class Attachment(models.Model):
    """
    Files attached to messages, internal or synced from Gmail.
    """
    message = models.ForeignKey(Message, related_name='attachments', on_delete=models.CASCADE)
    file = models.FileField(upload_to='attachments/', blank=True, null=True)
    filename = models.CharField(max_length=255, blank=True, null=True)
    mime_type = models.CharField(max_length=100, blank=True, null=True)
    size = models.PositiveIntegerField(blank=True, null=True)

    def __str__(self):
        return self.filename or f"Attachment {self.id}"
