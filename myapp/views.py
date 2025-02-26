import email
from email.mime import image
from os import name
from urllib import request
from myapp.permissions import IsAdminOrTeacher, IsAdminUser
from myapp.serializers import BulkUserCreateSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()


from itsdangerous import URLSafeTimedSerializer
from django.urls import reverse

# Create a serializer instance
serializer = URLSafeTimedSerializer(settings.SECRET_KEY)

from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework import status
from django.urls import reverse
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from itsdangerous import URLSafeTimedSerializer
from .models import Profile, Role, User  # Assuming Role model exists

# Initialize serializer for email verification token
serializer = URLSafeTimedSerializer(settings.SECRET_KEY)
class SignupView(APIView):
    # permission_classes = [IsAdminOrTeacher]

    def post(self, request):
        name = request.data.get("name")
        email = request.data.get("email")
        password = request.data.get("password")
        role_id = request.data.get("role_id")  # Get role_id from request
        image = request.FILES.get("image")  # Get profile image

        print("Received Data:", request.data)  # Debugging
        print("Received Files:", request.FILES)  # Debugging

        # Validate required fields
        if not name or not email or not password or not role_id:
            return Response({"error": "All fields including role_id are required"}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({"error": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)

        # Hash the password before saving
        user = User.objects.create(
            username=name,
            email=email,
            password=make_password(password)
        )

        # Assign role (Check if role exists)
        try:
            role_id = int(role_id)  # Convert role_id to integer
            role = Role.objects.get(id=role_id)
            print(f"Role Assigned: {role}")  # Debugging
        except (ValueError, Role.DoesNotExist):
            return Response({"error": "Invalid role ID"}, status=status.HTTP_400_BAD_REQUEST)

        # Create profile with image and role
        profile = Profile.objects.create(user=user, image=image, role=role)
        print(f"Created Profile: {profile}")  # Debugging

        # Generate a secure token for email verification
        token = serializer.dumps(email, salt="email-confirm")

        # Create a verification link
        verification_url = request.build_absolute_uri(
            reverse("verify-email", kwargs={"token": token})
        )

        # Load the email template and replace variables
        email_body = render_to_string("email_verified.html", {
            "name": name,
            "verification_url": verification_url
        })

        # Send the email
        subject = "Verify Your Email"
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [email]

        email_message = EmailMultiAlternatives(subject, "", from_email, recipient_list)
        email_message.attach_alternative(email_body, "text/html")
        email_message.send()

        return Response({"message": "User created successfully. Please check your email to verify your account."}, status=status.HTTP_201_CREATED)

# class SignupView(APIView):
#     permission_classes = [IsAdminOrTeacher]

#     def post(self, request):
#         name = request.data.get("name")
#         email = request.data.get("email")
#         password = request.data.get("password")
#         role_id = request.data.get("role_id")  # Get role_id from request
#         image = request.FILES.get("image")  # Get profile image

#         print("Received Data:", request.data)  # Debugging
#         print("Received Files:", request.FILES)  # Debugging

#         # Validate required fields
#         if not name or not email or not password or not role_id:
#             return Response({"error": "All fields including role_id are required"}, status=status.HTTP_400_BAD_REQUEST)

#         if User.objects.filter(email=email).exists():
#             return Response({"error": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)

#         # Hash the password before saving
#         user = User.objects.create(
#             username=name,
#             email=email,
#             password=make_password(password)
#         )

#         # Assign role (Check if role exists)
#         try:
#             role_id = int(role_id)  # Convert role_id to integer
#             role = Role.objects.get(id=role_id)
#         except (ValueError, Role.DoesNotExist):
#             return Response({"error": "Invalid role ID"}, status=status.HTTP_400_BAD_REQUEST)

#         # Create profile with image and role
#         profile = Profile.objects.create(user=user, image=image, role=role)
#         print(f"Created Profile: {profile}")  # Debugging

#         # Generate a secure token for email verification
#         token = serializer.dumps(email, salt="email-confirm")

#         # Create a verification link
#         verification_url = request.build_absolute_uri(
#             reverse("verify-email", kwargs={"token": token})
#         )

#         # Load the email template and replace variables
#         email_body = render_to_string("email_verified.html", {
#             "name": name,
#             "verification_url": verification_url
#         })

#         # Send the email
#         subject = "Verify Your Email"
#         from_email = settings.EMAIL_HOST_USER
#         recipient_list = [email]

#         email_message = EmailMultiAlternatives(subject, "", from_email, recipient_list)
#         email_message.attach_alternative(email_body, "text/html")
#         email_message.send()

#         return Response({"message": "User created successfully. Please check your email to verify your account."}, status=status.HTTP_201_CREATED)


# class SignupView(APIView):
#     permission_classes = [IsAdminOrTeacher]

#     def post(self, request):
#         name = request.data.get("name")
#         email = request.data.get("email")
#         password = request.data.get("password")
#         role_id = request.data.get("role_id")  # New: Assign role
#         image = request.FILES.get("image")  # New: Handle image upload
#         print("Received Data:", request.data)
#         print("Received Files:", request.FILES)
#         # Validate required fields
#         if not name or not email or not password:
#             return Response({"error": "All fields are required"}, status=status.HTTP_400_BAD_REQUEST)

#         if User.objects.filter(email=email).exists():
#             return Response({"error": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)

#         # Hash the password before saving
#         user = User.objects.create(
#             username=name,
#             email=email,
#             password=make_password(password)  # Securely hash password
#         )

#         # Assign role (if Role model exists)
#         role = None
#         if role_id:
#             try:
#                 role_id = int(role_id)  # Convert role_id to integer
#                 role = Role.objects.filter(id=role_id).first()
#                 if not role:
#                     return Response({"error": "Invalid role ID"}, status=status.HTTP_400_BAD_REQUEST)
#             except ValueError:
#                 return Response({"error": "Invalid role ID"}, status=status.HTTP_400_BAD_REQUEST)
#             # role = Role.objects.filter(id=role_id).first()

#         # Create profile with image
#         # Profile.objects.create(user=user, ima/ge=image, role=role)
#     profile = Profile.objects.create(user=User, image=image, role=Role)

        
#         # Generate a secure token for email verification
#     token = serializer.dumps(email, salt="email-confirm")

#         # Create a verification link
#     verification_url = request.build_absolute_uri(
#             reverse("verify-email", kwargs={"token": token})
#         )

#         # Load the email template and replace variables
#     email_body = render_to_string("email_verified.html", {
#             "name": name,
#             "verification_url": verification_url
#         })

#         # Send the email
#     subject = "Verify Your Email"
#     from_email = settings.EMAIL_HOST_USER
#     recipient_list = [email]

#     email_message = EmailMultiAlternatives(subject, "", from_email, recipient_list)
#     email_message.attach_alternative(email_body, "text/html")
#     email_message.send()

#     return Response({"message": "User created successfully. Please check your email to verify your account."}, status=status.HTTP_201_CREATED)


# from django.template.loader import render_to_string
# from django.core.mail import EmailMultiAlternatives

# class SignupView(APIView):
#     permission_classes = []

#     def post(self, request):
#         name = request.data.get("name")
#         email = request.data.get("email")
#         password = request.data.get("password")
#         role_id = request.data.get("role_id")  # New: Assign role
#         image = request.FILES.get("image")

#         if not name or not email or not password:
#             return Response({"error": "All fields are required"}, status=status.HTTP_400_BAD_REQUEST)

#         if User.objects.filter(email=email).exists():
#             return Response({"error": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)

#         user = User.objects.create(
#             username=name,
#             email=email,
#             password=make_password(password)
#         )

#         # Generate a secure token
#         token = serializer.dumps(email, salt="email-confirm")

#         # Create a verification link
#         verification_url = request.build_absolute_uri(
#             reverse("verify-email", kwargs={"token": token})
#         )

#         # Load the email template and replace variables
#         email_body = render_to_string("email_verified.html", {
#             "name": name,
#             "verification_url": verification_url
#         })

#         # Send the email
#         subject = "Verify Your Email"
#         from_email = settings.EMAIL_HOST_USER
#         recipient_list = [email]

#         email_message = EmailMultiAlternatives(subject, "", from_email, recipient_list)
#         email_message.attach_alternative(email_body, "text/html")
#         email_message.send()

#         return Response({"message": "User created successfully. Please check your email to verify your account."}, status=status.HTTP_201_CREATED)

# from rest_framework_simplejwt.tokens import RefreshToken
# from rest_framework.decorators import api_view, permission_classes
# from rest_framework_simplejwt.tokens import RefreshToken
# from rest_framework.decorators import api_view, permission_classes
# from rest_framework.response import Response
# from rest_framework.permissions import AllowAny
# from .models import User

# @api_view(['POST'])
# @permission_classes([])
# def login(request):
#     username = request.data.get("username")
#     email = request.data.get("email")

#     user = User.objects.filter(username=username, email=email).first()
    
#     if user:
#         refresh = RefreshToken.for_user(user)
#         return Response({
#             "username": user.username,
#             "email": user.email,
#             "refresh": str(refresh),
#             "access": str(refresh.access_token)
#         })
#     else:
#         return Response({"error": "Invalid credentials"}, status=400)

from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response

@api_view(['POST'])
@permission_classes([])
def login(request):
    username = request.data.get("username")
    email = request.data.get("email")
    password = request.data.get("password")

    print("Received data:", request.data)  # Debugging

    if not username or not email or not password:
        return Response({"error": "All fields (username, email, password) are required."}, status=400)

    # Authenticate user
    user = authenticate(username=username, password=password)

    if user and user.email == email:  
        refresh = RefreshToken.for_user(user)

        # ✅ Secure HTTPS Redirect URL
        redirect_url = f"https://www.youtube.com/hashtag/youtubelink{user.id}/"

        # ✅ HTML email content with button
        html_message = f"""
        <html>
        <body>
            <p>Hello {user.username},</p>
            <p>You have successfully logged in. Click the button below to access your dashboard:</p>
            <p>
                <a href="{redirect_url}" style="background-color: #008CBA; color: white; padding: 10px 20px; text-decoration: none; display: inline-block; border-radius: 5px; font-size: 16px;">
                    Access Dashboard
                </a>
            </p>
            <p>If you did not attempt to log in, please ignore this email.</p>
        </body>
        </html>
        """

        # ✅ Send email with button link
        send_mail(
            "Login Successful - Redirect to Your Dashboard",
            "",  # Empty text message
            settings.EMAIL_HOST_USER,
            [user.email],
            fail_silently=False,
            html_message=html_message,  # ✅ Send HTML content
        )

        return Response({
            "username": user.username,
            "email": user.email,
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "redirect_url": redirect_url  # ✅ Include HTTPS redirect URL
        })
    else:
        return Response({"error": "Invalid credentials"}, status=400)

# @api_view(['POST'])
# @permission_classes([])
# def login(request):
#     username = request.data.get("username")
#     email = request.data.get("email")
#     password = request.data.get("password")  

#     print("Received data:", request.data)  # Debugging

#     if not username or not email or not password:
#         return Response({"error": "All fields (username, email, password) are required."}, status=400)

#     # Authenticate user
#     user = authenticate(username=username, password=password)

#     if user and user.email == email:  
#         refresh = RefreshToken.for_user(user)

#         # Redirect URL after login (modify as needed)
#         redirect_url = f"https://www.youtube.com/hashtag/youtubelink{user.id}"

#         return Response({
#             "username": user.username,
#             "email": user.email,
#             "refresh": str(refresh),
#             "access": str(refresh.access_token),
#             "redirect_url": redirect_url  # ✅ Include the redirect URL
#         })
#     else:
#         return Response({"error": "Invalid credentials"}, status=400)

from django.http import HttpResponse
from django.shortcuts import render
from itsdangerous.exc import BadSignature, SignatureExpired


class VerifyEmailView(APIView):
    permission_classes = [IsAdminOrTeacher]

    def get(self, request, token):
        try:
            email = serializer.loads(token, salt="email-confirm", max_age=3600)  # Expires in 1 hour
            user = User.objects.get(email=email)
            user.is_active = True  # Activate the user
            user.save()
            return render(request, "email_verified.html")  # Render a confirmation page

        except SignatureExpired:
            return HttpResponse("Verification link expired!", status=400)
        except BadSignature:
            return HttpResponse("Invalid verification link!", status=400)
        
from django.views.decorators.csrf import csrf_exempt
@csrf_exempt
def verify_email(request,token):
    return render(request, "myapp/email_verified.html")  



# Create a user
from django.core.mail import send_mail, EmailMessage
from django.conf import settings
from django.contrib.auth.models import User
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

@api_view(['POST'])
@permission_classes([IsAdminOrTeacher])
def create_user(request):
    data = request.data
    username = data['username']
    email = data.get('email', '')
    password = data['password']
    image = request.FILES.get('image')  # Handle file upload
    role_id = data.get('role_id')

    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        role = Role.objects.get(id=role_id)  # Fetch role from DB
    except Role.DoesNotExist:
        return Response({'error': 'Invalid role ID'}, status=status.HTTP_400_BAD_REQUEST)

    # Create user
    user = User.objects.create_user(username=username, email=email, password=password)

    # Save image in Profile model
    profile = Profile.objects.create(user=user, image=image, role_id=role_id)

    # ✅ Secure redirect URL
    dashboard_url = f"https://your-website.com/dashboard/{user.id}"

    # ✅ HTML Email with a button
    subject = "Welcome to Our Platform!"
    html_message = f"""
    <html>
    <body>
        <h2>Hi {username}, welcome to our platform!</h2>
        <p>Your account has been created successfully.</p>
        <p>Click the button below to access your dashboard:</p>
        <a href="{dashboard_url}" style="display: inline-block; padding: 10px 20px; font-size: 16px; 
        color: white; background-color: #007bff; text-decoration: none; border-radius: 5px;">
            Go to Dashboard
        </a>
        <p>If you did not sign up for this account, please ignore this email.</p>
    </body>
    </html>
    """

    # ✅ Send HTML email
    email_message = EmailMessage(
        subject,
        html_message,
        settings.DEFAULT_FROM_EMAIL,
        [email]
    )
    email_message.content_subtype = "html"  # Set email type to HTML
    email_message.send(fail_silently=False)

    return Response({'message': 'User created', 'id': user.id}, status=status.HTTP_201_CREATED)

# from django.contrib.auth.models import User
# from rest_framework.decorators import api_view, permission_classes
# from rest_framework.response import Response
# from rest_framework import status
# from django.core.mail import send_mail
# from django.conf import settings
# from .models import Profile,Role  # Assuming you have a Profile model for extra user fields

# @api_view(['POST'])
# # @permission_classes([IsAdminOrTeacher])
# def create_user(request):
#     data = request.data
#     username = data['username']
#     email = data.get('email', '')
#     password = data['password']
#     image = request.FILES.get('image')  # Handle file upload
#     role_id = data.get('role_id')
#     if not email:
#         return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
#     try:
#         role = Role.objects.get(id=role_id)  # Fetch role from DB
#     except Role.DoesNotExist:
#         return Response({'error': 'Invalid role ID'}, status=status.HTTP_400_BAD_REQUEST)
#     # Create user
#     user = User.objects.create_user(username=username, email=email,password=password)

#     # Save image in Profile model
#     profile = Profile.objects.create(user=user, image=image,role_id=role_id)
    
#     # Send welcome email
#     send_mail(
#         'Welcome to Our Platform!',
#         f'Hi {username}, welcome to our platform! Your account has been created successfully.',
#         settings.DEFAULT_FROM_EMAIL,
#         [email],
#         fail_silently=False,
#     )

#     return Response({'message': 'User created', 'id': user.id}, status=status.HTTP_201_CREATED)

@api_view(['GET'])
@permission_classes([IsAdminOrTeacher])
def get_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    return Response({'id': user.id, 'username': user.username, 'email': user.email, 'role':user.role_id}, status=status.HTTP_200_OK)

# Edit a user
@api_view(['PUT'])
@permission_classes([])
def user_edit(request, user_id):
    user = get_object_or_404(User, id=user_id)
    data = request.data

    user.first_name = data.get('first_name', user.first_name)
    user.last_name = data.get('last_name', user.last_name)
    user.email = data.get('email', user.email)

    if 'password' in data:
        user.set_password(data['password'])  # Hash the password before saving

    if 'role_id' in data:
        role = Role.objects.filter(id=data['role_id']).first()
        if role:
            user.role = role  # Assuming `role` is a ForeignKey

    user.save()
    return Response({'message': 'User updated successfully'}, status=status.HTTP_200_OK)

# Delete a user
@api_view(['DELETE'])
@permission_classes([IsAdminOrTeacher])
def user_delete(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.delete()
    return Response({"message": "User deleted successfully."}, status=status.HTTP_200_OK)

# List users or get details of a specific user
from django.contrib.auth.models import User
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from .models import Profile  # Assuming you have a Profile model
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from .models import User, Profile  # Ensure these models are correctly imported

@api_view(['GET'])
@permission_classes([])
def user_list(request, user_id=None):
    if user_id:
        user = get_object_or_404(User, id=user_id)
        profile = Profile.objects.filter(user=user).first()
        
        full_name = f"{user.first_name} {user.last_name}".strip()
        name = full_name if full_name else user.username  # Use username if full_name is empty
        
        return Response({
            "id": user.id,
            "name": name,
            "email": user.email,
            "role": profile.role.id if profile and profile.role else None,  # ✅ FIXED

            # "role": profile.role.name if hasattr(user, 'role') else None,
            "image": request.build_absolute_uri(profile.image.url) if profile and profile.image else None
        }, status=status.HTTP_200_OK)
    
    else:
        users = User.objects.all().values("id", "first_name", "last_name", "username", "email")
        user_list = []

        for user in users:
            profile = Profile.objects.filter(user_id=user["id"]).first()
            full_name = f"{user['first_name']} {user['last_name']}".strip()
            name = full_name if full_name else user["username"]  # Use username if first_name & last_name are empty
            
            user_list.append({
                "id": user["id"],
                "name": name,
                "email": user["email"],
                "role": profile.role.id if profile and profile.role else None,  # ✅ FIXED

                # "role": user.role.name if hasattr(user, 'role') else None,
                "image": request.build_absolute_uri(profile.image.url) if profile and profile.image else None
            })

        return Response({"users": user_list}, status=status.HTTP_200_OK)

@api_view(['POST', 'GET', 'PUT', 'DELETE'])
@permission_classes([])
def role_crud(request, role_id=None):
    if request.method == 'POST':
        name = request.data.get('name')

        if Role.objects.filter(name=name).exists():
            return Response({"error": f"Role {name} already exists."}, status=status.HTTP_400_BAD_REQUEST)

        role = Role(name=name)
        role.save()
        return Response({"message": f"Role {name} created successfully."}, status=status.HTTP_201_CREATED)

    if request.method == 'GET':
        if role_id:
            try:
                role = Role.objects.get(id=role_id)
                return Response({"id": role.id, "name": role.name})
            except Role.DoesNotExist:
                return Response({"error": "Role not found."}, status=status.HTTP_404_NOT_FOUND)
        else:
            roles = Role.objects.all().values()
            return Response({"roles": list(roles)})

    if request.method == 'PUT':
        try:
            role = Role.objects.get(id=role_id)
            role.name = request.data.get('name', role.name)
            role.save()
            return Response({"message": "Role updated successfully."})
        except Role.DoesNotExist:
            return Response({"error": "Role not found."}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        try:
            role = Role.objects.get(id=role_id)
            role.delete()
            return Response({"message": "Role deleted successfully."})
        except Role.DoesNotExist:
            return Response({"error": "Role not found."}, status=status.HTTP_404_NOT_FOUND)




from django.contrib.auth.models import User
from django.utils.crypto import get_random_string
from django.core.mail import send_mail, EmailMultiAlternatives
from django.core.cache import cache
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

class RequestPasswordReset(APIView):
    permission_classes = []

    def post(self, request):
        email = request.POST.get('email')
        user = User.objects.filter(email=email).first()

        if user:
            token = get_random_string(32)
            cache.set(token, user.id, timeout=3600)  # Store token for 1 hour

            reset_link = f"{settings.FRONTEND_URL}/reset-password/{token}/"

            subject = "Password Reset Request"
            from_email = "no-reply@example.com"
            to_email = [email]

            # Plain text fallback
            text_content = f"Click the link to reset your password: {reset_link}"

            # HTML Email with a button
            html_content = f"""
            <html>
            <body>
                <p>Hello,</p>
                <p>Click the button below to reset your password:</p>
                <a href="{reset_link}" style="
                    display: inline-block;
                    background-color: #007bff;
                    color: white;
                    padding: 10px 20px;
                    text-decoration: none;
                    font-size: 16px;
                    border-radius: 5px;
                ">Reset Password</a>
                <p>If you didn’t request this, you can ignore this email.</p>
            </body>
            </html>
            """

            email_message = EmailMultiAlternatives(subject, text_content, from_email, to_email)
            email_message.attach_alternative(html_content, "text/html")
            email_message.send()

            return Response({'message': 'Password reset link sent to email'}, status=status.HTTP_200_OK)

        return Response({'error': 'Email not found'}, status=status.HTTP_400_BAD_REQUEST)



class ResetPassword(APIView):
    permission_classes = []

    def post(self, request):
        user_id = request.POST.get('user_id')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if new_password != confirm_password:
            return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
        
        user = get_object_or_404(User, id=user_id)
        user.set_password(new_password)
        user.save()

        return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)


from django.contrib.auth.hashers import make_password
from myapp.models import Role, User  # ✅ Import User and Role models
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
import pandas as pd

class BulkUserCreateView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = BulkUserCreateSerializer(data=request.data)
        if serializer.is_valid():
            file = serializer.validated_data['file']
            
            try:
                df = pd.read_excel(file)

                # Ensure required columns exist
                required_columns = {'username', 'email', 'password', 'role'}
                if not required_columns.issubset(df.columns):
                    return Response({"error": "Excel file must contain columns: username, email, password, role"},
                                    status=status.HTTP_400_BAD_REQUEST)

                users_created = 0
                for _, row in df.iterrows():
                    if not User.objects.filter(username=row['username']).exists():
                        role_instance = Role.objects.filter(name=row['role'].strip().lower()).first()
                        
                        if not role_instance:
                            return Response({"error": f"Invalid role: {row['role']}"}, 
                                            status=status.HTTP_400_BAD_REQUEST)

                        # ✅ Create the user instance
                        user = User()
                        user.username = row['username']
                        user.email = row['email']
                        user.password = make_password(row['password'])  # ✅ Hash password
                        user.role = role_instance  # ✅ Assign ForeignKey properly

                        user.save()  # ✅ Save the user instance correctly
                        users_created += 1

                return Response({"message": f"{users_created} users created successfully."}, 
                                status=status.HTTP_201_CREATED)

            except Exception as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

