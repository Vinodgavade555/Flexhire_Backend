# Generated by Django 4.2.15 on 2024-10-14 10:31

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0017_companydocuments'),
    ]

    operations = [
        migrations.RenameField(
            model_name='companydocuments',
            old_name='document',
            new_name='documents',
        ),
    ]
