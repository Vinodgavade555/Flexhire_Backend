# Generated by Django 4.2.15 on 2024-10-15 03:45

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0020_rename_document_companydocuments_documents'),
    ]

    operations = [
        migrations.RenameField(
            model_name='companydocuments',
            old_name='documents',
            new_name='document',
        ),
    ]
