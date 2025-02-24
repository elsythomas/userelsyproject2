from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth.views import LoginView

from .views import (
    SignupView,
    VerifyEmailView,
    create_user,
    get_user,
    user_edit,
    user_delete,
    user_list,
    RequestPasswordReset,
    ResetPassword,
)

urlpatterns = [
    # Authentication URLs
    path("signup/", SignupView.as_view(), name="signup"),
    path("verify-email/<str:token>/", VerifyEmailView.as_view(), name="verify-email"),
    path("login/", LoginView.as_view(template_name="login.html"), name="login"),
    
    # User Management URLs
    path('users/', user_list, name='user_list'),
    path('users/create/', create_user, name='create_user'),
    path('users/<int:user_id>/', get_user, name='get_user'),
    path('users/<int:user_id>/edit/', user_edit, name='user_edit'),
    path('users/<int:user_id>/delete/', user_delete, name='user_delete'),
    
    # Password Reset URLs
    path('api/request-password-reset/', RequestPasswordReset.as_view(), name='request-password-reset'),
    path('api/reset-password/', ResetPassword.as_view(), name='reset-password'),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)




# from django.urls import path
# from django.conf import settings
# from django.conf.urls.static import static
# from django.contrib.auth.views import LoginView  # Add this import

# from.views import SignupView,VerifyEmailView,create_user, get_user,create_user, get_user, user_edit, user_delete, user_list,RequestPasswordReset,ResetPassword
# [
#     path("signup/", SignupView.as_view(), name="signup"),
#     path("verify-email/<str:token>/", VerifyEmailView.as_view(), name="verify-email"),
#     path("login/", LoginView.as_view(template_name="login.html"), name="login"),
#     #  path('users/create/', create_user, name='create_user'),  # Create a new user
#     path('users/<int:user_id>/', get_user, name='get_user'),  # Get user details
#     path('users/<int:user_id>/edit/', user_edit, name='user_edit'),  # Edit user details
#     path('users/<int:user_id>/delete/', user_delete, name='user_delete'),  # Delete a user
#     path('users/', user_list, name='user_list'),  # List all users
#     path('create/', create_user, name='create_user'),
#      path('api/request-password-reset/', RequestPasswordReset.as_view(), name='request-password-reset'),
#     path('api/reset-password/', ResetPassword.as_view(), name='reset-password'),
#     # path('register/', create_user, name='register'),
#     # path('<int:user_id>/', get_user, name='get_user'),
#     # path('<int:user_id>/edit/', edit_user, name='edit_user'),
#     # path('<int:user_id>/delete/', delete_user, name='delete_user'),
#     # path("reset-password/<uidb64>/<token>/", reset_password_view, name="reset_password"),
#     # path("request-password-reset/", RequestPasswordReset.as_view(), name="request-password-reset"),
#     # path("password-reset/<str:token>/", ResetPasswordView.as_view(), name="password-reset"),
#     # path('users/', get_users, name='get_users'),
#     # path("reset-password/<int:user_id>/", reset_password, name="api_reset_password"),
#     # path("api/reset-password/<int:user_id>/", ResetPasswordAPIView.as_view(), name="api_reset_password"),

# ]

# if settings.DEBUG:
#     urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)