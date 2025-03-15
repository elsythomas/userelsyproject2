import json
from django.shortcuts import get_object_or_404
from django.core.signing import Signer
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from django.urls import reverse
from myapp import serializers
from myapp.models import Student, Role, Profile  
from myapp.utils import USER_STATUS
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from myproject.logging_config import logger


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
    try:
        print(1/0)
    except Exception  as e :
        print (str(e))
        logger.info(str(e))

        
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
            "name": user.name,  
            "email": user.email,
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "redirect_url": redirect_url
        })

    except User.DoesNotExist:
        return Response({"error": "Invalid credentials"}, status=400)



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

from openpyxl import load_workbook
import os
import pandas as pd

EXCEL_FILE = "C:\\Users\\Elsy Thomas\\Downloads\\users.xlsx"

def update_google_sheet(user):
    """
    Updates the Excel sheet with a new user entry.
    """
    # Check if the file exists
    if not os.path.exists(EXCEL_FILE):
        df = pd.DataFrame(columns=["ID", "Name", "Email", "Role", "Status"])
        df.to_excel(EXCEL_FILE, index=False)

    # Load the existing Excel file
    df = pd.read_excel(EXCEL_FILE)

    # Append new user data
    new_data = pd.DataFrame([{
        "ID": user.id,
        "Name": user.name,
        "Email": user.email,
        "Role": user.role.name if user.role else "No Role",
        "Status": "Pending"
    }])

    df = pd.concat([df, new_data], ignore_index=True)

    # Save back to Excel
    df.to_excel(EXCEL_FILE, index=False)




from django.core.cache import cache
from django.core.mail import EmailMessage
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from .models import Student, Role
from .permissions import IsAdminOrTeacher
from .utils import update_google_sheet, update_user_status_in_google_sheet
import redis

redis_client = redis.StrictRedis(host='localhost', port=6379, db=0)

# Initialize Excel when the app starts


@api_view(['POST'])
@permission_classes([IsAdminOrTeacher])
def create_user(request):
    print(f"User: {request.user}, Role: {getattr(request.user.role, 'name', 'No Role')}")

    if not request.user.is_authenticated:
        return Response({"error": "Authentication required"}, status=401)

    data = request.data
    name = data.get('username')  
    email = data.get('email')
    password = data.get('password')
    role_id = data.get('role_id')

    if not email or not name or not password:
        return Response({'error': 'Name, email, and password are required'}, status=status.HTTP_400_BAD_REQUEST)


    #  Cache role for efficiency
    cache_key = f"role_{role_id}"
    role = cache.get(cache_key)
    if not role:
        role = Role.objects.filter(id=role_id).first()
        if not role:
            return Response({'error': 'Invalid role ID'}, status=status.HTTP_400_BAD_REQUEST)
        cache.set(cache_key, role,)

    #  Create a new user with "Pending" status
    user = Student.objects.create_user(email=email, password=password, name=name, role=role)
    user.is_active = False  # User is inactive initially
    user.save()

    # Update Excel after user creation
    update_google_sheet(user)

    #  Send Password Reset Email
    reset_url = f"https://your-website.com/reset-password/{user.id}"
    redis_client.setex(f"reset_url:{user.id}",5, reset_url)

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

    email_message = EmailMessage(
        subject,
        html_message,
        settings.DEFAULT_FROM_EMAIL,
        [email]
    )
    email_message.content_subtype = "html"
    email_message.send(fail_silently=False)

    return Response({'message': 'User created. Please reset your password to activate the account.', 'id': user.id}, status=status.HTTP_201_CREATED)




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
def user_list(request, user_id=None):
    if user_id:
        cache_key = f"user_{user_id}"  # Unique Redis key for each user
        cached_user = cache.get(cache_key)

        if cached_user:
            print(" Cache hit! user data.")
            return Response({"message": "Cache hit!", "user": json.loads(cached_user)}, status=status.HTTP_200_OK)

        print(" Cache miss! Fetching from the database.")
        user = get_object_or_404(Student, id=user_id)
        
        user_data = {
            "id": user.id,
            "name": user.name.strip(),
            "email": user.email,
            "role": user.role.id if user.role else None,
            "image": request.build_absolute_uri(user.image.url) if user.image else None,
            "status": "active" if user.is_active else "pending"
        }

        cache.set(cache_key, json.dumps(user_data))  #no time
        return Response({"message": "Cache miss! Data stored.", "user": user_data}, status=status.HTTP_200_OK)

    else:
        cache_key = "user_list_cache1"
        cached_users = cache.get(cache_key)

        if cached_users:
            print(" Cache hit! Returning cached user list.")
            return Response({"message": "Cache hit!", "users": json.loads(cached_users)}, status=status.HTTP_200_OK)

        print(" Cache miss! Fetching user list from the database.")
        users = Student.objects.all()
        user_list = []

        for user in users:
            user_list.append({
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role.id if user.role else None,
                "image": request.build_absolute_uri(user.image.url) if user.image else None,
                "status": "active" if user.is_active else "pending"
            })

        cache.set(cache_key, json.dumps(user_list))  # no time
        return Response({"message": "Cache miss! Data stored.", "users": user_list}, status=status.HTTP_200_OK)





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
  # Ensure you import the correct permission class

User = get_user_model()

@api_view(['POST'])
@permission_classes([])  #  Restrict to Admins/Teachers if needed
def update_password(request):
    user_id = request.data.get("user_id")  #  Use user_id instead of email
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
    user.is_active = True  #  Activate user only after password update
    user.save()

    #  Update last login timestamp (optional)
    update_last_login(None, user)
    update_user_status_in_google_sheet(user.email, "Active")

    return Response({"message": "Password reset successful, user is now active"}, status=status.HTTP_200_OK)



from django.contrib.auth.hashers import make_password
from myapp.models import Role, Student  #  Import User and Role models
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
import pandas as pd

class BulkUserCreateView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = serializers.BulkUserCreateSerializer(data=request.data)
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
                    if not User.objects.filter(name=row['username']).exists():
                        role_instance = Role.objects.filter(name=row['role'].strip().lower()).first()
                        
                        if not role_instance:
                            return Response({"error": f"Invalid role: {row['role']}"}, 
                                            status=status.HTTP_400_BAD_REQUEST)

                        #  Create the user instance
                        user = User(
                        name=row['username'],  #  Use 'name' instead of 'username'
                        email=row['email'],
                        password=make_password(row['password']),
                        role=role_instance  
                        )
                        
                        user.save()  #  Save the user instance correctly
                        users_created += 1

                return Response({"message": f"{users_created} users created successfully."}, 
                                status=status.HTTP_201_CREATED)

            except Exception as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt  
from myproject.logging_config import logger  

@csrf_exempt  
def test_logging(request):
    logger.info("This is a test log message!")
    return HttpResponse("Logging is working! Check the console and django.log file.")
