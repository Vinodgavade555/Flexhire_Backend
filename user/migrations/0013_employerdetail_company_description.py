# Generated by Django 4.2.15 on 2024-10-11 06:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0012_remove_user_parent_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='employerdetail',
            name='company_description',
            field=models.CharField(blank=True, max_length=512, null=True),
        ),
    ]