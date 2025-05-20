from django.db import migrations
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password

def create_superuser(apps, schema_editor):
    User = get_user_model()
    if not User.objects.filter(username='admin').exists():
        User.objects.create(
            username='admin',
            password=make_password('yourpassword123'),
            is_superuser=True,
            is_staff=True,
            email='admin@example.com'
        )

class Migration(migrations.Migration):

    dependencies = [
        ('mentorapp', '0009_update_payment_fields'),  # Change as needed
    ]

    operations = [
        migrations.RunPython(create_superuser),
    ]
