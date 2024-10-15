# Generated by Django 4.2.15 on 2024-10-14 07:21

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0014_remove_employerdetail_contact_person_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='CompanyDetails',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('company_name', models.CharField(max_length=255)),
                ('company_description', models.CharField(blank=True, max_length=512, null=True)),
                ('email', models.EmailField(max_length=254, null=True, unique=True)),
                ('company_address', models.TextField(blank=True, null=True)),
                ('industry', models.CharField(max_length=100)),
                ('website', models.CharField(blank=True, max_length=255, null=True)),
                ('BusinessRegistrationNumber', models.EmailField(max_length=254, null=True, unique=True)),
                ('TaxIdentificationNumber', models.EmailField(max_length=254, null=True, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='employer_created_by', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AlterField(
            model_name='contactdetail',
            name='employer',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='contact_details', to='user.companydetails'),
        ),
        migrations.DeleteModel(
            name='EmployerDetail',
        ),
    ]
