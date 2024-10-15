# Generated by Django 4.2.15 on 2024-10-10 05:24

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0004_user_is_active'),
    ]

    operations = [
        migrations.CreateModel(
            name='EmployerDetail',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('company_name', models.CharField(max_length=255)),
                ('company_address', models.TextField(blank=True, null=True)),
                ('contact_person', models.CharField(blank=True, max_length=255, null=True)),
                ('industry', models.CharField(max_length=100)),
                ('phone_number', models.CharField(blank=True, max_length=15, null=True)),
                ('website', models.URLField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('employer', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='employer_detail', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
