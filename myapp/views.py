from django.shortcuts import get_object_or_404
from django.core.signing import Signer
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from django.urls import reverse
from myapp import serializers
from myapp.models import Student, Role, Profile  # ✅ Correct import
from myapp.utils import USER_STATUS
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

class SignupView(APIView):
    def post(self, request):
        name = request.data.get("name")
        email = request.data.get("email")
        password = request.data.get("password")
        role_id = request.data.get("role_id")
        image = request.FILES.get("image")

        print("Received Data:", request.data)
        print("Received Files:", request.FILES)
        print("Received Role ID:", role_id)

        # Validate input
        if not name or not email or not password or not role_id:
            return Response({"error": "All fields including role_id are required"}, status=status.HTTP_400_BAD_REQUEST)

        if Student.objects.filter(email=email).exists():
            return Response({"error": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)

        # Validate role
        try:
            role = Role.objects.get(id=role_id)
        except Role.DoesNotExist:
            return Response({"error": "Invalid role ID"}, status=status.HTTP_400_BAD_REQUEST)

        # Create user with role
        user = Student(email=email, name=name, role=role, image=image)
        user.set_password(password)
        user.save()

        # Create profile with image
        profile = Profile.objects.create(user=user, image=image if image else None,role=role )
        print(f"Created Profile: {profile}")

        # Email verification logic remains the same
        signer = Signer()
        token = signer.sign(email)
        verification_url = request.build_absolute_uri(reverse("verify-email", kwargs={"token": token}))

        email_body = render_to_string("email_verified.html", {
            "name": name,
            "verification_url": verification_url
        })

        subject = "Verify Your Email"
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [email]

        email_message = EmailMultiAlternatives(subject, "", from_email, recipient_list)
        email_message.attach_alternative(email_body, "text/html")
        email_message.send()

        return Response({"message": "User created successfully. Check your email for verification."}, status=status.HTTP_201_CREATED)

# # from profile import Profile
# from django.shortcuts import get_object_or_404
# from django.core.signing import Signer
# from django.template.loader import render_to_string
# from django.core.mail import EmailMultiAlternatives
# from django.conf import settings
# from django.urls import reverse
# from myapp import serializers
# from myapp.permissions import IsAdminOrTeacher
# from rest_framework.response import Response
# from rest_framework.views import APIView
# from rest_framework import status
# from myapp.models import Student, Role,Profile
# from rest_framework.permissions import IsAuthenticated


# class SignupView(APIView):
#     def post(self, request):
#         name = request.data.get("name")
#         email = request.data.get("email")
#         password = request.data.get("password")
#         role_id = request.data.get("role_id")  # Get role_id from request
#         image = request.FILES.get("image")  # Get profile image

#         print("Received Data:", request.data)  # Debugging
#         print("Received Files:", request.FILES)  # Debugging
#         print("Received Role ID:", role_id)  # Debugging

#         # Validate required fields
#         if not name or not email or not password or role_id is None:
#             return Response({"error": "All fields including role_id are required"}, status=status.HTTP_400_BAD_REQUEST)

#         # Check if email already exists
#         if Student.objects.filter(email=email).exists():
#             return Response({"error": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)

#         # Get role
#         role = get_object_or_404(Role, id=role_id)

#         # Create user
#         user = Student(email=email, name=name, role=role)
#         user.set_password(password)  # Secure password hashing
#         user.save()

#         # Create profile
#         profile = Profile.objects.create(user=user, image=image if image else None)
#         print(f"Created Profile: {profile}")  # Debugging

#         # Generate a secure token for email verification
#         signer = Signer()
#         token = signer.sign(email)

#         # Create a verification link
#         verification_url = request.build_absolute_uri(reverse("verify-email", kwargs={"token": token}))

#         # Load email template and replace variables
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

# from django.contrib.auth import get_user_model
# from django.contrib.auth.hashers import make_password
# from myapp.permissions import IsAdminOrTeacher
# from rest_framework.response import Response
# from rest_framework.views import APIView
# from rest_framework import status
# from django.urls import reverse
# from django.template.loader import render_to_string
# from django.core.mail import EmailMultiAlternatives
# from django.conf import settings
# from itsdangerous import URLSafeTimedSerializer
# from .models import Profile, Role

# User = get_user_model()  # ✅ Use the correct user model

# # Initialize serializer for email verification token
# serializer = URLSafeTimedSerializer(settings.SECRET_KEY)

# class SignupView(APIView):
#     def post(self, request):
#         name = request.data.get("name")
#         email = request.data.get("email")
#         password = request.data.get("password")
#         role_id = request.data.get("role_id")  # Get role_id from request
#         image = request.FILES.get("image")  # Get profile image

#         print("Received Data:", request.data)  # Debugging
#         print("Received Files:", request.FILES)  # Debugging
#         print("Received Role ID:", role_id) 
#         if not name or not email or not password or role_id is None:
#             return Response({"error": "All fields including role_id are required"}, status=status.HTTP_400_BAD_REQUEST)
#  # Debugging

#         # Validate require
#         if Student.objects.filter(email=email).exists():
#             return Response({"error": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)

#         # Convert role_id safely
#         try:
#             role_id = int(role_id)
#             role = Role.objects.get(id=role_id)
#         except ValueError:
#             return Response({"error": "Role ID must be an integer"}, status=status.HTTP_400_BAD_REQUEST)
#         except Role.DoesNotExist:
#             return Response({"error": "Invalid role ID"}, status=status.HTTP_400_BAD_REQUEST)  
#             # return Response({"error": "Invalid role ID"}, status=status.HTTP_400_BAD_REQUEST)

#         # Create user (Django hashes password automatically)
#         user = Student.objects.create_user(email=email, name=name, password=password)

#         # Create profile
#         profile = Profile.objects.create(user=user, image=image, role=role)
#         print(f"Created Profile: {profile}")  # Debugging

#         # Generate a secure token for email verification
#         token = serializer.dumps(email, salt="email-confirm")

#         # Create a verification link
#         verification_url = request.build_absolute_uri(reverse("verify-email", kwargs={"token": token}))

#         # Load email template and replace variables
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


# import email
# from email.mime import image
# from os import name
# from urllib import request
# from myapp.permissions import   IsAdminOrTeacher, IsAuthenticatedAndInAdminGroup
# from myapp.serializers import BulkUserCreateSerializer
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from django.contrib.auth.models import User
# from django.contrib.auth.hashers import make_password
# from django.core.mail import send_mail
# from django.conf import settings
# from django.contrib.auth import get_user_model

# User = get_user_model()


# from itsdangerous import URLSafeTimedSerializer
# from django.urls import reverse

# # Create a serializer instance
# serializer = URLSafeTimedSerializer(settings.SECRET_KEY)

# from django.contrib.auth.models import User
# from django.contrib.auth.hashers import make_password
# from rest_framework.response import Response
# from rest_framework.views import APIView
# from rest_framework.permissions import AllowAny
# from rest_framework import status
# from django.urls import reverse
# from django.template.loader import render_to_string
# from django.core.mail import EmailMultiAlternatives
# from django.conf import settings
# from itsdangerous import URLSafeTimedSerializer
# from .models import Profile, Role, Student  # Assuming Role model exists

# # Initialize serializer for email verification token
# serializer = URLSafeTimedSerializer(settings.SECRET_KEY)
# class SignupView(APIView):
#     # permission_classes = [IsAdminOrTeacher]

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
#             name=name,
#             email=email,
#             password=make_password(password)
#         )

#         # Assign role (Check if role exists)
#         try:
#             role_id = int(role_id)  # Convert role_id to integer
#             role = Role.objects.get(id=role_id)
#             print(f"Role Assigned: {role}")  # Debugging
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
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from django.conf import settings

User = get_user_model()

@api_view(["POST"])
@permission_classes([])
def login(request):
    email = request.data.get("email")
    password = request.data.get("password")

    print("Received data:", request.data)  # Debugging

    # Validate input
    if not email or not password:
        return Response({"error": "Email and password are required."}, status=400)

    try:
        # Fetch user by email
        user = User.objects.get(email=email)
        
        # Verify password
        if not user.check_password(password):  
            return Response({"error": "Invalid credentials"}, status=400)

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)

        # Secure redirect URL
        redirect_url = f"https://www.youtube.com/hashtag/youtubelink{user.id}/"

        # Email content
        html_message = f"""
        <html>
        <body>
            <p>Hello {user.name},</p>
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

        # Send email
        send_mail(
            "Login Successful - Redirect to Your Dashboard",
            "",  # Empty text message
            settings.EMAIL_HOST_USER,
            [user.email],
            fail_silently=False,
            html_message=html_message,
        )

        return Response({
            "name": user.name,  # ✅ Use "name" instead of "username"
            "email": user.email,
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "redirect_url": redirect_url
        })

    except User.DoesNotExist:
        return Response({"error": "Invalid credentials"}, status=400)

# from rest_framework.decorators import api_view, permission_classes
# from rest_framework.response import Response
# from django.contrib.auth import authenticate, get_user_model
# from rest_framework_simplejwt.tokens import RefreshToken

# User = get_user_model()
# from django.core.mail import send_mail
# from django.conf import settings
# from django.contrib.auth import authenticate
# from rest_framework_simplejwt.tokens import RefreshToken
# from rest_framework.decorators import api_view, permission_classes
# from rest_framework.response import Response

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
#     user = authenticate(email=email, password=password)

#     if user and user.email == email:  
#         refresh = RefreshToken.for_user(user)

#         # ✅ Secure HTTPS Redirect URL
#         redirect_url = f"https://www.youtube.com/hashtag/youtubelink{user.id}/"

#         # ✅ HTML email content with button
#         html_message = f"""
#         <html>
#         <body>
#             <p>Hello {user.username},</p>
#             <p>You have successfully logged in. Click the button below to access your dashboard:</p>
#             <p>
#                 <a href="{redirect_url}" style="background-color: #008CBA; color: white; padding: 10px 20px; text-decoration: none; display: inline-block; border-radius: 5px; font-size: 16px;">
#                     Access Dashboard
#                 </a>
#             </p>
#             <p>If you did not attempt to log in, please ignore this email.</p>
#         </body>
#         </html>
#         """

#         # ✅ Send email with button link
#         send_mail(
#             "Login Successful - Redirect to Your Dashboard",
#             "",  # Empty text message
#             settings.EMAIL_HOST_USER,
#             [user.email],
#             fail_silently=False,
#             html_message=html_message,  # ✅ Send HTML content
#         )

#         return Response({
#             "username": user.username,
#             "email": user.email,
#             "refresh": str(refresh),
#             "access": str(refresh.access_token),
#             "redirect_url": redirect_url  # ✅ Include HTTPS redirect URL
#         })
#     else:
#         return Response({"error": "Invalid credentials"}, status=400)

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
    # permission_classes = [IsAdminOrTeacher]

    def get(self, request, token):
        try:
            email = serializers.loads(token, salt="email-confirm", max_age=3600)  # Expires in 1 hour
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
from django.core.mail import EmailMessage
from django.conf import settings
from myapp.models import Student, Role
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status

from .permissions import IsAdminOrTeacher ,IsAdmin # Ensure this is imported

@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdminOrTeacher])
def create_user(request):
    # return Response("sucess") 
    print(f"User: {request.user}, Role: {getattr(request.user.role, 'name', 'No Role')}")
    

    if not request.user.is_authenticated:
        return Response({"error": "Authentication required"}, status=401)

    data = request.data
    name = data.get('username')  # Store username as name
    email = data.get('email')
    password = data.get('password')
    image = request.FILES.get('image')  # Handle file upload
    role_id = data.get('role_id')

    if not email or not name or not password:
        return Response({'error': 'Name, email, and password are required'}, status=status.HTTP_400_BAD_REQUEST)

    # Get role
    role = Role.objects.filter(id=role_id).first()
    if not role:
        return Response({'error': 'Invalid role ID'}, status=status.HTTP_400_BAD_REQUEST)

    # ✅ Create user with status "Pending"
    user = Student.objects.create_user(email=email, password=password, name=name, role=role)
    user.is_active = False  # Deactivate the user initially
    user.save()

    # ✅ Create Profile & Save Image
    # profile, _ = profile.objects.get_or_create(user=user, defaults={"image": image})

    # ✅ Secure redirect URL for password reset
    reset_url = f"https://your-website.com/reset-password/{user.id}"

    # ✅ Email Notification
    subject = "Welcome! Please Reset Your Password"
    html_message = f"""
    <html>
    <body>
        <h2>Hi {name}, welcome to our platform!</h2>
        <p>Your account has been created successfully, but you need to reset your password before activation.</p>
        <p>Click the button below to set your new password:</p>
        <a href="{reset_url}" style="display: inline-block; padding: 10px 20px; font-size: 16px; 
        color: white; background-color: #007bff; text-decoration: none; border-radius: 5px;">
            Reset Password
        </a>
        <p>After resetting, your account will be activated.</p>
    </body>
    </html>
    """

    #  Send Email
    email_message = EmailMessage(
        subject,
        html_message,
        settings.DEFAULT_FROM_EMAIL,
        [email]
    )
    email_message.content_subtype = "html"
    email_message.send(fail_silently=False)

    return Response({'message': 'User created. Please reset your password to activate the account.', 'id': user.id}, status=status.HTTP_201_CREATED)

# from django.core.mail import send_mail, EmailMessage
# from django.conf import settings
# from myapp.models import Student
# from rest_framework.permissions import IsAuthenticated


# # from django.contrib.auth.models import User
# from rest_framework.decorators import api_view
# from rest_framework.response import Response
# from rest_framework import status
# from myapp.models import Role, Profile

# @api_view(['POST'])
# @permission_classes([IsAuthenticated,IsAdminOrTeacher])
# def create_user(request):
#     print(f"User: {request.user}, Role: {getattr(request.user.role, 'name', 'No Role')}")
#     if not request.user.is_authenticated:
#         return Response({"error": "Authentication required"}, status=401)
#     data = request.data
#     username = data.get('username')
#     email = data.get('email')
#     password = data.get('password')
#     image = request.FILES.get('image')  # Handle file upload
#     role_id = data.get('role_id')  # ✅ Assign role

#     if not email or not username or not password:
#         return Response({'error': 'Username, email, and password are required'}, status=status.HTTP_400_BAD_REQUEST)

#     # Get role
#     role = Role.objects.filter(id=role_id).first()
#     if not role:
#         return Response({'error': 'Invalid role ID'}, status=status.HTTP_400_BAD_REQUEST)

#     # ✅ Create user and assign role
#     user = User.objects.create_user(name=username, email=email, password=password,role=role)

#     # ✅ Save or create profile
#     profile, created = Profile.objects.get_or_create(user=user, defaults={"image": image})

#     # ✅ Secure redirect URL
#     dashboard_url = f"https://your-website.com/dashboard/{user.id}"

#     # ✅ HTML Email with a button
#     subject = "Welcome to Our Platform!"
#     html_message = f"""
#     <html>
#     <body>
#         <h2>Hi {username}, welcome to our platform!</h2>
#         <p>Your account has been created successfully.</p>
#         <p>Click the button below to access your dashboard:</p>
#         <a href="{dashboard_url}" style="display: inline-block; padding: 10px 20px; font-size: 16px; 
#         color: white; background-color: #007bff; text-decoration: none; border-radius: 5px;">
#             Go to Dashboard
#         </a>
#         <p>If you did not sign up for this account, please ignore this email.</p>
#     </body>
#     </html>
#     """

#     # ✅ Send HTML email
#     email_message = EmailMessage(
#         subject,
#         html_message,
#         settings.DEFAULT_FROM_EMAIL,
#         [email]
#     )
#     email_message.content_subtype = "html"  # Set email type to HTML
#     email_message.send(fail_silently=False)

#     return Response({'message': 'User created', 'id': user.id}, status=status.HTTP_201_CREATED)

# @api_view(['POST'])
# @permission_classes([IsAdminOrTeacher])
# def create_user(request):
#     data = request.data
#     username = data['username']
#     email = data.get('email', '')
#     password = data['password']
#     image = request.FILES.get('image')  # Handle file upload
#     # role_id = data.get('role_id')

#     if not email:
#         return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
    
#     # try:
#         # role = Role.objects.get(id=role_id)  # Fetch role from DB
#     # except Role.DoesNotExist:
#         # return Response({'error': 'Invalid role ID'}, status=status.HTTP_400_BAD_REQUEST)

#     # Create user
#     user = User.objects.create_user(username=username, email=email, password=password)

#     # Save image in Profile model
#     profile = Profile.objects.create(user=user, image=image)

#     # ✅ Secure redirect URL
#     dashboard_url = f"https://your-website.com/dashboard/{user.id}"

#     # ✅ HTML Email with a button
#     subject = "Welcome to Our Platform!"
#     html_message = f"""
#     <html>
#     <body>
#         <h2>Hi {username}, welcome to our platform!</h2>
#         <p>Your account has been created successfully.</p>
#         <p>Click the button below to access your dashboard:</p>
#         <a href="{dashboard_url}" style="display: inline-block; padding: 10px 20px; font-size: 16px; 
#         color: white; background-color: #007bff; text-decoration: none; border-radius: 5px;">
#             Go to Dashboard
#         </a>
#         <p>If you did not sign up for this account, please ignore this email.</p>
#     </body>
#     </html>
#     """

#     # ✅ Send HTML email
#     email_message = EmailMessage(
#         subject,
#         html_message,
#         settings.DEFAULT_FROM_EMAIL,
#         [email]
#     )
#     email_message.content_subtype = "html"  # Set email type to HTML
#     email_message.send(fail_silently=False)

#     return Response({'message': 'User created', 'id': user.id}, status=status.HTTP_201_CREATED)

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
    return Response({'id': user.id, 'name': user.name, 'email': user.email, 'role':user.role_id}, status=status.HTTP_200_OK)

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


from myapp.models import Student  
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404

@api_view(['GET'])
@permission_classes([])
def user_list(request, user_id=None):
    if user_id:
        user = get_object_or_404(Student, id=user_id)

        full_name = f"{user.name}".strip()

        return Response({
            "id": user.id,
            "name": full_name,
            "email": user.email,
            "role": user.role.id if user.role else None,  
            "image": request.build_absolute_uri(user.image.url) if user.image and hasattr(user.image, "url") else None ,
            "status": "active" if user.is_active else "pending"
        }, status=status.HTTP_200_OK)

    else:
        users = Student.objects.all()  # ✅ Fetch full objects instead of .values()

        user_list = []
        for user in users:
            user_list.append({
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role.id if user.role else None,
                "image": request.build_absolute_uri(user.image.url) if user.image else None,  # ✅ Now image is returned
                "status": USER_STATUS[0][1] if user.is_active else USER_STATUS[1][1]
            })

        return Response({"users": user_list}, status=status.HTTP_200_OK)


# from myapp.models import Student  # Import Student instead of User
# from rest_framework.decorators import api_view, permission_classes
# from rest_framework.response import Response
# from rest_framework import status
# from django.shortcuts import get_object_or_404

# @api_view(['GET'])
# @permission_classes([])
# def user_list(request, user_id=None):
#     if user_id:
#         user = get_object_or_404(Student, id=user_id)  # Change User to Student

#         full_name = f"{user.name}".strip()  # Since 'name' is used instead of 'first_name' and 'last_name'

#         return Response({
#             "id": user.id,
#             "name": full_name,
#             "email": user.email,
#             "role": user.role.id if user.role else None,  
#             "image": request.build_absolute_uri(user.image.url) if user.image else None,  
#             "status": "active" if user.is_active else "pending"
#         }, status=status.HTTP_200_OK)

#     else:
#         users = Student.objects.all()

#         user_list = []
#         for user in users:
#             user_list.append({
#                 "id": user["id"],
#                 "name": user["name"],
#                 "email": user["email"],
#                 "role": user["role_id"],
#                 "image": None,
#                 "status": "active" if user["is_active"] else "pending"
#             })

#         return Response({"users": user_list}, status=status.HTTP_200_OK)

# List users or get details of a specific user
# from myapp.models import User
# from rest_framework.decorators import api_view, permission_classes
# from rest_framework.response import Response
# from rest_framework import status
# from django.shortcuts import get_object_or_404
# # from .models import Profile  # Assuming you have a Profile model
# from rest_framework.decorators import api_view, permission_classes
# from rest_framework.response import Response
# from rest_framework import status
# from django.shortcuts import get_object_or_404
# from .models import Student  # Ensure these models are correctly imported

# @api_view(['GET'])
# @permission_classes([])
# def user_list(request, user_id=None):
#     if user_id:
#         user = get_object_or_404(User, id=user_id)
#         profile = Profile.objects.filter(user=user).first()

#         full_name = f"{user.first_name} {user.last_name}".strip()
#         name = full_name if full_name else user.username  # Use username if full_name is empty

#         return Response({
#             "id": user.id,
#             "name": name,
#             "email": user.email,
#             "role": profile.role.id if profile and profile.role else None,
#             "image": request.build_absolute_uri(profile.image.url) if profile and profile.image else None,
#             "status": "active" if user.is_active else "pending"  # ✅ Added status field
#         }, status=status.HTTP_200_OK)
    
#     else:
#         users = User.objects.all().values("id", "first_name", "last_name", "username", "email", "is_active")
#         user_list = []

#         for user in users:
#             profile = Profile.objects.filter(user_id=user["id"]).first()
#             full_name = f"{user['first_name']} {user['last_name']}".strip()
#             name = full_name if full_name else user["username"]

#             user_list.append({
#                 "id": user["id"],
#                 "name": name,
#                 "email": user["email"],
#                 "role": profile.role.id if profile and profile.role else None,
#                 "image": request.build_absolute_uri(profile.image.url) if profile and profile.image else None,
#                 "status": "active" if user["is_active"] else "pending"  # ✅ Added status field
#             })

#         return Response({"users": user_list}, status=status.HTTP_200_OK)
# @api_view(['GET'])
# @permission_classes([])
# def user_list(request, user_id=None):
#     if user_id:
#         user = get_object_or_404(User, id=user_id)
#         profile = Profile.objects.filter(user=user).first()
        
#         full_name = f"{user.first_name} {user.last_name}".strip()
#         name = full_name if full_name else user.username  # Use username if full_name is empty
        
#         return Response({
#             "id": user.id,
#             "name": name,
#             "email": user.email,
#             "role": profile.role.id if profile and profile.role else None,  # ✅ FIXED

#             # "role": profile.role.name if hasattr(user, 'role') else None,
#             "image": request.build_absolute_uri(profile.image.url) if profile and profile.image else None
#         }, status=status.HTTP_200_OK)
    
#     else:
#         users = User.objects.all().values("id", "first_name", "last_name", "username", "email")
#         user_list = []

#         for user in users:
#             profile = Profile.objects.filter(user_id=user["id"]).first()
#             full_name = f"{user['first_name']} {user['last_name']}".strip()
#             name = full_name if full_name else user["username"]  # Use username if first_name & last_name are empty
            
#             user_list.append({
#                 "id": user["id"],
#                 "name": name,
#                 "email": user["email"],
#                 "role": profile.role.id if profile and profile.role else None,  # ✅ FIXED

#                 # "role": user.role.name if hasattr(user, 'role') else None,
#                 "image": request.build_absolute_uri(profile.image.url) if profile and profile.image else None
#             })

#         return Response({"users": user_list}, status=status.HTTP_200_OK)

@api_view(['POST', 'GET', 'PUT', 'DELETE'])
@permission_classes([IsAdmin])
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





from django.contrib.auth.models import update_last_login
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
from myapp.permissions import IsAdminOrTeacher  # Ensure you import the correct permission class

User = get_user_model()

@api_view(['POST'])
@permission_classes([IsAdminOrTeacher])  # ✅ Restrict to Admins/Teachers if needed
def update_password(request):
    user_id = request.data.get("user_id")  # ✅ Use user_id instead of email
    new_password = request.data.get("new_password")
    confirm_password = request.data.get("confirm_password")

    if not user_id or not new_password or not confirm_password:
        return Response({"error": "User ID, new password, and confirm password are required"}, status=status.HTTP_400_BAD_REQUEST)

    if new_password != confirm_password:
        return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    user.set_password(new_password)
    user.is_active = True  # ✅ Activate user only after password update
    user.save()

    # ✅ Update last login timestamp (optional)
    update_last_login(None, user)

    return Response({"message": "Password reset successful, user is now active"}, status=status.HTTP_200_OK)

# from django.contrib.auth.models import update_last_login
# from rest_framework.decorators import api_view,permission_classes
# from rest_framework.response import Response
# from rest_framework import status
# from django.contrib.auth import get_user_model

# User = get_user_model()
# @api_view(['POST'])
# @permission_classes([IsAdminOrTeacher])  # ✅ Allows anyone to reset their password

# def update_password(request):
#     email = request.data.get("email")
#     new_password = request.data.get("new_password")
#     confirm_password = request.data.get("confirm_password")  # ✅ Added confirm password

#     if not new_password or not confirm_password:
#         return Response({"error": "Both new password and confirm password are required"}, status=status.HTTP_400_BAD_REQUEST)

#     if new_password != confirm_password:
#         return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)

#     user = User.objects.filter(email=email).first()
#     if not user:
#         return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

#     user.set_password(new_password)
#     user.is_active = True  # ✅ Activate user after password reset
#     user.save()

#     # Optionally, update last login timestamp
#     update_last_login(None, user)

#     return Response({"message": "Password reset successful, user is now active"}, status=status.HTTP_200_OK)

# @api_view(['POST'])
# def reset_password(request):
#     email = request.data.get("email")
#     new_password = request.data.get("new_password")

#     user = User.objects.filter(email=email).first()
#     if not user:
#         return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

#     user.set_password(new_password)
#     user.is_active = True  # ✅ Activate user after password reset
#     user.save()

#     # Optionally, update last login timestamp
#     update_last_login(None, user)

#     return Response({"message": "Password reset successful, user is now active"}, status=status.HTTP_200_OK)


# class ResetPassword(APIView):
#     permission_classes = []

#     def post(self, request):
#         user_id = request.POST.get('user_id')
#         new_password = request.POST.get('new_password')
#         confirm_password = request.POST.get('confirm_password')

#         if new_password != confirm_password:
#             return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
        
#         user = get_object_or_404(User, id=user_id)
#         user.set_password(new_password)
#         user.save()

#         return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)


from django.contrib.auth.hashers import make_password
from myapp.models import Role, Student  # ✅ Import User and Role models
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

