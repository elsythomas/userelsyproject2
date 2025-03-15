from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth.views import LoginView


from .views import (
    SignupView,
    login,
    VerifyEmailView,
    create_user,
    get_user,
    test_logging,
    user_edit,
    user_delete,
    user_list,
    # RequestPasswordReset,
    update_password,
    role_crud,
    BulkUserCreateView,

)

urlpatterns = [
    # Authentication URLs
    path("signup/", SignupView.as_view(), name="signup"),
    path("verify-email/<str:token>/", VerifyEmailView.as_view(), name="verify-email"),
    path('login/', login, name='login'),
    path('bulk-user-upload/', BulkUserCreateView.as_view(), name='bulk-user-upload'),
   
     path('user-list/<int:user_id>/', user_list, name='user-detail'),

    # path("login/", LoginView.as_view(template_name="login.html"), name="login"),
    
    # User Management URLs
    path('users/', user_list, name='user_list'),
    path('users/create/', create_user, name='create_user'),
    path('users/<int:user_id>/', get_user, name='get_user'),
    path('users/<int:user_id>/edit/', user_edit, name='user_edit'),
    path('users/<int:user_id>/delete/', user_delete, name='user_delete'),
    path("test-log/", test_logging, name ='test-log'),
    
    
    #ROLE Urls
    path('api/roles/', role_crud, name='role_crud'),
    path('api/roles/<int:role_id>/', role_crud, name='role_crud_detail'),

    # Password Reset URLs
    # path('api/request-password-reset/', RequestPasswordReset.as_view(), name='request-password-reset'),
    path('update-password/', update_password, name='update-password'),
    
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


# path("test-log/", test_logging),