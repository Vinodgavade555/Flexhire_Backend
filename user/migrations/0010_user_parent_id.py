# Generated by Django 4.2.15 on 2024-10-10 09:33

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0009_alter_employerdetail_website'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='parent_Id',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='children', to=settings.AUTH_USER_MODEL),
        ),
    ]
