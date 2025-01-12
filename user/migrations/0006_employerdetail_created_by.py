# Generated by Django 4.2.15 on 2024-10-10 05:38

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0005_employerdetail'),
    ]

    operations = [
        migrations.AddField(
            model_name='employerdetail',
            name='created_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='employer_created_by', to=settings.AUTH_USER_MODEL),
        ),
    ]
