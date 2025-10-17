from django.db import models
from django.conf import settings

class Conversation(models.Model):
    subject = models.CharField(max_length=255)
    participants = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='conversations')
    thread_id = models.CharField(max_length=255, unique=True, null=True, blank=True)  # link to email thread
    created_at = models.DateTimeField(auto_now_add=True)

class Message(models.Model):
    conversation = models.ForeignKey(Conversation, related_name='messages', on_delete=models.CASCADE)
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    content = models.TextField()
    sent_at = models.DateTimeField(auto_now_add=True)
    email_id = models.CharField(max_length=255, null=True, blank=True)  # link to real email ID
