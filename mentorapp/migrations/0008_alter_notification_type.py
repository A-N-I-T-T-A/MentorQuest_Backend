# Generated by Django 5.1.7 on 2025-04-03 12:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mentorapp', '0007_payment_created_at_payment_updated_at_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='notification',
            name='type',
            field=models.CharField(choices=[('request', 'Request'), ('acceptance', 'Acceptance'), ('session', 'Session'), ('message', 'Message'), ('feedback', 'Feedback'), ('system', 'System'), ('skill', 'Skill'), ('booking', 'Booking')], max_length=15),
        ),
    ]
