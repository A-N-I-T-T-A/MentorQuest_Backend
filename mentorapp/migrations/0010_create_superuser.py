from django.db import migrations
from django.contrib.auth.hashers import make_password

def create_superuser(apps, schema_editor):
    User = apps.get_model('auth', 'User')
    if not User.objects.filter(username='admin').exists():
        User.objects.create(
            username='admin',
            password=make_password('admin'),
            is_superuser=True,
            is_staff=True,
            email='admin@gmail.com'
        )

class Migration(migrations.Migration):

    dependencies = [
        ('mentorapp', '0009_update_payment_fields'),  # Update to match your latest
    ]

    operations = [
        migrations.RunPython(create_superuser),
    ]
