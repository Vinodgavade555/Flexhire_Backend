from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
import os
from django.conf import settings
class UserRole(models.Model):
    role_id = models.AutoField(primary_key=True)
    role_name = models.CharField(max_length=50, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    parent = models.ForeignKey('self', null=True, blank=True, 
                               on_delete=models.CASCADE, 
                               related_name='sub_roles')

    def __str__(self):
        return self.role_name

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)  # Use set_password to hash the password
        user.save(using=self._db)
        return user

    # def create_superuser(self, email, password=None, **extra_fields):
    #     extra_fields.setdefault('is_staff', True)
    #     extra_fields.setdefault('is_superuser', True)
    #     return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser):
    user_id = models.AutoField(primary_key=True)  # Explicitly define user_id as primary key
    mobile_number = models.CharField(max_length=10, unique=True, null=True)
    email = models.EmailField(unique=True, null=True)
    social_media_id = models.CharField(max_length=255, unique=True, null=True)
    password = models.CharField(max_length=255)  # No longer nullable
    user_type = models.ForeignKey(UserRole, on_delete=models.CASCADE)
    created_by = models.ForeignKey('self', null=True, blank=True, on_delete=models.SET_NULL, related_name='created_users')
    is_active = models.BooleanField(default=False ,null=True,blank=True) 
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return f"User - {self.email if self.email else 'No Email'}"

class CompanyDetails(models.Model):
    company_name = models.CharField(max_length=255)
    company_description = models.CharField(max_length=512, null=True, blank=True)
    email = models.EmailField(unique=True, null=True)
    company_address = models.TextField(null=True, blank=True)
    industry = models.CharField(max_length=100)  # Add industry field
    website = models.CharField(max_length=255, null=True, blank=True)
    BusinessRegistrationNumber = models.CharField(max_length=100,unique=True, null=True)
    TaxIdentificationNumber = models.CharField(max_length=100,unique=True, null=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='employer_created_by')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.company_name


class ContactDetail(models.Model):
    person_name = models.CharField(max_length=255)
    position = models.CharField(max_length=255)
    mobile_number = models.CharField(max_length=10, null=True, blank=True)
    email = models.EmailField(unique=True, null=True)
    employer = models.ForeignKey(CompanyDetails, on_delete=models.CASCADE, related_name='contact_details')

    def __str__(self):
        return self.person_name
    
    
def file_location(instance, filename, **kwargs):
    file_path = f"document_files/{instance.employer.company_name}-{filename}"
    return file_path

class CompanyDocuments(models.Model):
    employer = models.ForeignKey(CompanyDetails, on_delete=models.CASCADE, related_name='documents')
    document_name = models.CharField(max_length=255)
    document_path = models.FileField(upload_to=file_location, null=True, blank=True)

    def delete(self, *args, **kwargs):
        if os.path.isfile(self.document_path.path):
            os.remove(self.document_path.path)
        super(CompanyDocuments, self).delete(*args, **kwargs)

