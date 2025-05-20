from django.db import migrations, models
from django.core.validators import MinValueValidator

class Migration(migrations.Migration):

    dependencies = [
        ('mentorapp', '0008_alter_notification_type'),
    ]

    operations = [
        migrations.AlterField(
            model_name='payment',
            name='amount',
            field=models.DecimalField(decimal_places=2, max_digits=10, validators=[MinValueValidator(0)]),
        ),
        migrations.AlterField(
            model_name='payment',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, null=True),
        ),
        migrations.AlterField(
            model_name='payment',
            name='updated_at',
            field=models.DateTimeField(auto_now=True, null=True),
        ),
    ]
