# Generated by Django 4.2.15 on 2024-10-15 04:09

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0021_rename_documents_companydocuments_document'),
    ]

    operations = [
        migrations.RenameField(
            model_name='companydocuments',
            old_name='document',
            new_name='document_path',
        ),
    ]