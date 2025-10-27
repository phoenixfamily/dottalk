# user/migrations/000X_add_auth_token.py
from django.db import migrations, models
import secrets


def generate_unique_auth_tokens(apps, schema_editor):
    User = apps.get_model('user', 'User')
    existing_tokens = set()

    for user in User.objects.all():
        # تولید token یکتا
        token = secrets.token_urlsafe(32)
        while token in existing_tokens:
            token = secrets.token_urlsafe(32)
        existing_tokens.add(token)
        user.auth_token = token
        user.save()


class Migration(migrations.Migration):
    dependencies = [
        ('user', 'previous_migration_name'),  # <- اینو با آخرین migration خودت جایگزین کن
    ]

    operations = [
        # اضافه کردن فیلد auth_token بدون unique
        migrations.AddField(
            model_name='user',
            name='auth_token',
            field=models.CharField(max_length=128, null=True, blank=True),
        ),
        # پر کردن فیلد با token های یکتا
        migrations.RunPython(generate_unique_auth_tokens),
        # تغییر فیلد برای unique=True
        migrations.AlterField(
            model_name='user',
            name='auth_token',
            field=models.CharField(max_length=128, unique=True),
        ),
    ]
