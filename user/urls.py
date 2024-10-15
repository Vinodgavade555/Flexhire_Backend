from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from .views import UserRoleAPIView, RegisterUserAPIView,AdminLoginView,CompanyDocumentsAPIView,UserLoginAPIView,CompanyDetailListAPIView,getAllUsersAPIView,ContactDetailCreateAPIView,getUserProfiledataAPIView,EmployerAdminLoginView,EmployerAdminCreateUserAPIView,AdminCreateUserAPIView,CompanyDetailserializerCreateAPIView,LoginAPI,GetRoleByParentAPIView
urlpatterns = [
    # User Role URLs
    path('role/', UserRoleAPIView.as_view(), name='user-role-list-create'),
    path('register_user/', RegisterUserAPIView.as_view(), name='user-list-create'),  # For listing and creating users

    path('user_login/', UserLoginAPIView.as_view(), name='user-login'),
    path('userProfile/<int:user_id>/', getUserProfiledataAPIView.as_view(), name='user-Profile'),  # For getting, updating, and deleting a user by ID
    path('get_all_users/', getAllUsersAPIView.as_view(), name='all_users'),  # For getting, updating, and deleting a user by ID

    path('admin_login/', AdminLoginView.as_view(), name='Asdmin_login'),
    path('employer_login/', EmployerAdminLoginView.as_view(), name='employer-admin-login'),

    path('register_employer_team/', EmployerAdminCreateUserAPIView.as_view(), name='employer-admin-create-user'),
    path('register_admin_team/', AdminCreateUserAPIView.as_view(), name='Admin_Create_Hiring_Partne'),

    path('company_details/', CompanyDetailserializerCreateAPIView.as_view(), name='employer-detail-list'),  # For creating and listing
    path('contact-details/', ContactDetailCreateAPIView.as_view(), name='contact-detail-create'),
    path('get_companies_details/', CompanyDetailListAPIView.as_view(), name='company-detail-list'),  # GET API
     path('company_documents/', CompanyDocumentsAPIView.as_view(), name='company-documents-list'),  # For GET and POST
    path('company_documents/<int:pk>/', CompanyDocumentsAPIView.as_view(), name='company-documents-detail'),  # For GET, PUT, DELETE

    path('roll_by_parent/', GetRoleByParentAPIView.as_view(), name='roll_by_parent'),  # For getting, updating, and deleting
    path('roll_by_parent/<int:parent>/', GetRoleByParentAPIView.as_view(), name='roll_by_parent_id'),  # For getting, updating, and deleting
]
if settings.DEBUG:
    urlpatterns += static(settings.DOCUMENT_FILES_URL, document_root=settings.DOCUMENT_FILES_ROOT)