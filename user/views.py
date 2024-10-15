from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status,permissions,serializers,generics
from django.contrib.auth.hashers import check_password
from django.contrib.auth import login
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User, UserRole,CompanyDetails,CompanyDocuments
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import ValidationError
from django.db import transaction
import base64
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import UserSerializer, UserRoleSerializer,CompanyDocumentsSerializer,CompanyDetailSerializer,LoginUserSerializer,LoginSerializer,ContactDetailSerializer
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model

User = get_user_model()

# View to manage user roles (list and create)
class UserRoleAPIView(APIView):
    def get(self, request):
        try:
            roles = UserRole.objects.all()
            serializer = UserRoleSerializer(roles, many=True)
            return Response(serializer.data)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        try:
            serializer = UserRoleSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"detail": "Role created successfully."}, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# View to manage user registration and CRUD operations
class RegisterUserAPIView(APIView):
   def post(self, request):
        try:
            serializer = UserSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserLoginAPIView(APIView):
    def post(self, request, *args, **kwargs):
        try:
            serializer = LoginSerializer(data=request.data)
            if serializer.is_valid():
                user = serializer.validated_data
                # Generate tokens
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                login(request, user)
                return Response({
                    "detail": "Login successful.",
                    "user": UserSerializer(user).data,
                    "email": user.email,  # Returning the user's email
                    "tokens": {
                        "refresh": str(refresh),
                        "access": access_token
                    },
                }, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        except ValidationError as e:
            return Response({"detail": "Invalid credentials."}, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            return Response({"detail": "An error occurred during login."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#this is for only user can see their profile
class getUserProfiledataAPIView(APIView):
    def get(self, request, user_id=None):
        try:
            if user_id:  # If user_id is provided, fetch that specific user
                user = get_object_or_404(User, id=user_id)
                serializer = UserSerializer(user)
                return Response(serializer.data)
            else:  # If no user_id is provided, list all users
                users = User.objects.all()
                serializer = UserSerializer(users, many=True)
                return Response(serializer.data)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#Admin Login View from suraj which not used it is used for referance
class LoginAPI(generics.GenericAPIView):
    serializer_class = LoginUserSerializer

    def post(self, request, *args, **kwargs):

        email_add = request.data["email"].lower()
        user_exist = User.objects.filter(email=email_add).exists()
        if not user_exist:
            raise serializers.ValidationError("User does not exists!!")

        context = {
            "email": email_add,
            "password": request.data["password"],
        }
        try:
            serializer = self.get_serializer(data=context)
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data
            refresh = RefreshToken.for_user(user)

            return Response(
                {
                    "message": "Logged In successfully!",
                    "user": UserSerializer(user).data,
                    # "token": AuthToken.objects.create(user)[1]
                    "token": str(refresh.access_token),
                }
            )

        except User.DoesNotExist:
            raise serializers.ValidationError("User does not exists!")


#Admin Login View Admin 
class AdminLoginView(APIView):
   def post(self, request, *args, **kwargs):
        try:
            serializer = LoginSerializer(data=request.data)
            if serializer.is_valid():
                user = serializer.validated_data

                # Generate tokens
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                login(request, user)

                return Response({ 
                    "detail": "Login successful.",
                    "user": UserSerializer(user).data,
                    "tokens": {
                        "refresh": str(refresh),
                        "access": access_token
                    },
                }, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#this is for only admin can see all users profile
class getAllUsersAPIView(APIView):
     def get(self, request, user_id=None):
        try:
            if user_id:  # If user_id is provided, fetch that specific user
                user = get_object_or_404(User, id=user_id)
                serializer = UserSerializer(user)
                return Response(serializer.data)
            else:  # If no user_id is provided, list all users
                users = User.objects.all()
                serializer = UserSerializer(users, many=True)
                return Response(serializer.data)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#Empolyer_Admin Login View
class EmployerAdminLoginView(APIView):
    
    def post(self, request, *args, **kwargs):
        try:
            serializer = LoginSerializer(data=request.data)
            if serializer.is_valid():
                user = serializer.validated_data

                # Generate tokens
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                login(request, user)

                return Response({ 
                    "detail": "Login successful.",
                    "user": UserSerializer(user).data,
                    "tokens": {
                        "refresh": str(refresh),
                        "access": access_token
                    },
                }, status=status.HTTP_200_OK)
            
            # If serializer is invalid, return errors
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# View for creating employer users (only Employear admins can create them)
class EmployerAdminCreateUserAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            # Validate and save the new user
            serializer = UserSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# View for creating Hiring Partner (only admins can create them)
class AdminCreateUserAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            # Validate and save the new user
            serializer = UserSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(
                    {
                        "detail": "Hiring partner created successfully.",
                        "user": serializer.data
                    },
                    status=status.HTTP_201_CREATED
                )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

# View for creating Employer_Details(only Employer_admins can create them)
class CompanyDetailserializerCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            user = request.user
            print(user)  # You can remove this line in production            
            # Create the employer detail instance
            serializer = CompanyDetailSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

class ContactDetailCreateAPIView(APIView):
   def post(self, request, *args, **kwargs):
        serializer = ContactDetailSerializer(data=request.data)
        try:
            # Validate and save the new contact detail
            serializer.is_valid(raise_exception=True)  # This will raise an error if invalid
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        except serializers.ValidationError as e:
            # Handle validation errors
            return Response({"errors": e.detail}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # Handle other unexpected errors
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class CompanyDetailListAPIView(APIView):
    def get(self, request, *args, **kwargs):
        try:
            # Retrieve all company details
            companies = CompanyDetails.objects.all()
            serializer = CompanyDetailSerializer(companies, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Exception as e:
            # Log the error (optional)
            print(f"Error retrieving company details: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class CompanyDocumentsAPIView(APIView):
    def get(self, request, *args, **kwargs):
        try:
            # Retrieve all company documents
            documents = CompanyDocuments.objects.all()
            serializer = CompanyDocumentsSerializer(documents, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            # Log the error (optional)
            print(f"Error retrieving company documents: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request, *args, **kwargs):
        try:
            # Create a new company document
            serializer = CompanyDocumentsSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                document = serializer.save()
                return Response(CompanyDocumentsSerializer(document).data, status=status.HTTP_201_CREATED)

        except serializers.ValidationError as e:
            # Handle validation errors specifically
            return Response({"errors": e.detail}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # Handle any other unexpected errors
            print(f"Error creating company document: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetRoleByParentAPIView(APIView):
    # permission_classes = [IsAuthenticated]  # Requires the user to be authenticated
   def get(self, request, parent=None):
        try:
            if parent:  # Fetch roles with the given parent_id
                roles = UserRole.objects.filter(parent_id=parent)  # Use filter to get multiple roles
                
                if not roles.exists():
                    return Response({"detail": "No roles found for the given parent."}, status=status.HTTP_404_NOT_FOUND)

                serializer = UserRoleSerializer(roles, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)

            else:  # If no parent is provided, return all roles
                all_roles = UserRole.objects.all()
                serializer = UserRoleSerializer(all_roles, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            # Log the error (optional)
            print(f"Error fetching user roles: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)