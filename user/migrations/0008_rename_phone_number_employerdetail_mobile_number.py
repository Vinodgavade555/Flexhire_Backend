# Generated by Django 4.2.15 on 2024-10-10 07:02

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0007_remove_employerdetail_employer'),
    ]

    operations = [
        migrations.RenameField(
            model_name='employerdetail',
            old_name='phone_number',
            new_name='mobile_number',
        ),
    ]
