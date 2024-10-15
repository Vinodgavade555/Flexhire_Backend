from rest_framework import serializers
from .models import User, UserRole,CompanyDetails,ContactDetail,CompanyDocuments
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate
from drf_extra_fields.fields import Base64FileField
from django.core.files.base import ContentFile

class UserRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRole
        fields = ['role_id', 'role_name', 'created_at', 'parent']

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['user_id', 'mobile_number', 'email','social_media_id', 'password', 
                  'user_type','created_by','is_active','created_at', 'updated_at',]



    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data['password'])
        user = User(**validated_data)
        user.save()
        return user

    def update(self, instance, validated_data):
        if 'password' in validated_data:
            validated_data['password'] = make_password(validated_data['password'])
        return super().update(instance, validated_data)

#this code gets frm suraj as a referance 
class LoginUserSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):

        user = authenticate(**data)

        if user:
            if user.is_active:
                return user
            raise serializers.ValidationError("Account is not activated")
        raise serializers.ValidationError("Invalid Details.")


class LoginSerializer(serializers.Serializer):
    identifier = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        identifier = data.get("identifier")
        password = data.get("password")

        # Attempt to authenticate using email or mobile number
        if "@" in identifier:
            user = authenticate(email=identifier, password=password)
        else:
            user = authenticate(mobile_number=identifier, password=password)

        # Allow login if user is found and is active
        if user:
            if user.is_active:
                return user
            raise serializers.ValidationError({"identifier": "Account is not activated."})  # Error linked to 'identifier'
        
        # Return error based on identifier type
        if "@" in identifier:
            raise serializers.ValidationError({"identifier": "Email or password is incorrect."})
        else:
            raise serializers.ValidationError({"identifier": "Mobile number or password is incorrect."})

class ContactDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactDetail
        fields = ['person_name', 'position', 'mobile_number', 'email','employer']



class CompanyDocumentsSerializer(serializers.ModelSerializer):
    document_path = serializers.FileField(required = True)
    class Meta:
        model = CompanyDocuments
        fields = ['id','employer', 'document_name', 'document_path']
    def create(self, validated_data):

        return CompanyDocuments.objects.create(**validated_data)


class CompanyDetailSerializer(serializers.ModelSerializer):
    documents = serializers.SerializerMethodField()
    contact_details = ContactDetailSerializer(many=True, read_only=True)
    class Meta:
            model = CompanyDetails
            fields = ['company_name', 'company_description', 'company_address','email', 'industry', 'website','BusinessRegistrationNumber','TaxIdentificationNumber', 'created_by','contact_details','documents', 'created_at', 'updated_at']

    def get_documents(self, obj):
        documents = obj.documents.all()  # Ensure 'documents' is the correct related name
        return CompanyDocumentsSerializer(documents, many=True).data


