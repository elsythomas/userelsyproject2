from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.permissions import AllowAny
from itsdangerous import URLSafeTimedSerializer
from django.urls import reverse

# Create a serializer instance
serializer = URLSafeTimedSerializer(settings.SECRET_KEY)

# class SignupView(APIView):
#     permission_classes = [AllowAny]

#     def post(self, request):
#         name = request.data.get("name")
#         email = request.data.get("email")
#         password = request.data.get("password")

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
#         message = f"Hi {name},\n\nClick the link below to verify your email:\n\n{verification_url}\n\nBest regards,\nYour Company"
#         from_email = settings.EMAIL_HOST_USER
#         recipient_list = [email]

#         send_mail(subject, message, from_email, recipient_list, fail_silently=False)

#         return Response({"message": "User created successfully. Please check your email to verify your account."}, status=status.HTTP_201_CREATED)
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
from .models import Profile, Role  # Assuming Role model exists

# Initialize serializer for email verification token
serializer = URLSafeTimedSerializer(settings.SECRET_KEY)

class SignupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        name = request.data.get("name")
        email = request.data.get("email")
        password = request.data.get("password")
        role_id = request.data.get("role_id")  # New: Assign role
        image = request.FILES.get("image")  # New: Handle image upload

        # Validate required fields
        if not name or not email or not password:
            return Response({"error": "All fields are required"}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({"error": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)

        # Hash the password before saving
        user = User.objects.create(
            username=name,
            email=email,
            password=make_password(password)  # Securely hash password
        )

        # Assign role (if Role model exists)
        role = None
        if role_id:
            role = Role.objects.filter(id=role_id).first()

        # Create profile with image
        Profile.objects.create(user=user, image=image, role=role)

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


from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives

class SignupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        name = request.data.get("name")
        email = request.data.get("email")
        password = request.data.get("password")
        role_id = request.data.get("role_id")  # New: Assign role
        image = request.FILES.get("image")

        if not name or not email or not password:
            return Response({"error": "All fields are required"}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({"error": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create(
            username=name,
            email=email,
            password=make_password(password)
        )

        # Generate a secure token
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


from django.http import HttpResponse
from django.shortcuts import render
from itsdangerous.exc import BadSignature, SignatureExpired


class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

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


# from django.contrib.auth.models import User
# from rest_framework.response import Response
# from rest_framework.decorators import api_view
# from .serializers import UserSerializer

# @api_view(['GET'])
# def get_users(request):
#     user = User.objects.all()  # Fetch all users
#     serializer = UserSerializer(user, many=True)
#     return Response(serializer.data)

        

from django.contrib.auth.models import User
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
# import json
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
# from myapp.models import Role  # Import Role model

# Create a user
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from myapp.models import Role  # Import Role model

# Create a user
from django.contrib.auth.models import User
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from django.conf import settings
from .models import Profile  # Assuming you have a Profile model for extra user fields

@api_view(['POST'])
@permission_classes([])
def create_user(request):
    data = request.data
    username = data['username']
    email = data.get('email', '')
    password = data['password']
    image = request.FILES.get('image')  # Handle file upload

    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

    # Create user
    user = User.objects.create_user(username=username, email=email, password=password)

    # Save image in Profile model
    profile = Profile.objects.create(user=user, image=image)
    
    # Send welcome email
    send_mail(
        'Welcome to Our Platform!',
        f'Hi {username}, welcome to our platform! Your account has been created successfully.',
        settings.DEFAULT_FROM_EMAIL,
        [email],
        fail_silently=False,
    )

    return Response({'message': 'User created', 'id': user.id}, status=status.HTTP_201_CREATED)

# @api_view(['POST'])
# @permission_classes([])
# def create_user(request):
#     data = request.data
#     user = User.objects.create_user(
#         username=data['username'], 
#         email=data.get('email', ''), 
#         password=data['password']
        
#     )
#     return Response({'message': 'User created', 'id': user.id}, status=status.HTTP_201_CREATED)

# Get user details
@api_view(['GET'])
@permission_classes([])
def get_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    return Response({'id': user.id, 'username': user.username, 'email': user.email, 'role':user.role}, status=status.HTTP_200_OK)

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
@permission_classes([])
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

@api_view(['GET'])
@permission_classes([])
def user_list(request, user_id=None):
    if user_id:
        user = get_object_or_404(User, id=user_id)
        profile = Profile.objects.filter(user=user).first()  # Fetch profile if exists

        return Response({
            "id": user.id,
            "email": user.email,
            "role": user.role.name if hasattr(user, 'role') else None,
            "image": request.build_absolute_uri(profile.image.url) if profile and profile.image else None
        }, status=status.HTTP_200_OK)
    
    else:
        users = User.objects.all().values("id", "first_name", "last_name", "email")
        user_list = []

        for user in users:
            profile = Profile.objects.filter(user_id=user["id"]).first()
            user_list.append({
                "id": user["id"],
                "first_name": user["first_name"],
                "last_name": user["last_name"],
                "email": user["email"],
                "image": request.build_absolute_uri(profile.image.url) if profile and profile.image else None
            })

        return Response({"users": user_list}, status=status.HTTP_200_OK)

# @api_view(['GET'])
# @permission_classes([])
# def user_list(request, user_id=None):
#     if user_id:
#         user = get_object_or_404(User, id=user_id)
#         return Response({
#             "id": user.id,
#             # "first_name": user.first_name,
#             # "last_name": user.last_name,
#             "email": user.email,
#             "role": user.role.name if hasattr(user, 'role') else None,
#         }, status=status.HTTP_200_OK)
#     else:
#         users = User.objects.all().values("id", "first_name", "last_name", "email")
#         return Response({"users": list(users)}, status=status.HTTP_200_OK)



from django.contrib.auth.models import User
from django.utils.crypto import get_random_string
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.core.cache import cache  # Using cache to store tokens temporarily

# Endpoint to request a password reset
class RequestPasswordReset(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.POST.get('email')
        user = User.objects.filter(email=email).first()
        if user:
            token = get_random_string(32)
            cache.set(token, user.id, timeout=3600)  # Store token for 1 hour
            send_mail(
                'Password Reset Request',
                f'Use this token to reset your password: {token}',
                'no-reply@example.com',
                [email],
                fail_silently=False,
            )
            return Response({'message': 'Reset token sent to email'}, status=status.HTTP_200_OK)
        return Response({'error': 'Email not found'}, status=status.HTTP_400_BAD_REQUEST)

# Endpoint to reset password
class ResetPassword(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = request.POST.get('token')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if new_password != confirm_password:
            return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
        
        user_id = cache.get(token)
        if user_id:
            user = get_object_or_404(User, id=user_id)
            user.set_password(new_password)
            user.save()
            cache.delete(token)  # Remove token after use
            return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)
        
        return Response({'error': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)



