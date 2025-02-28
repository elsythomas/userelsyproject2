

# user details get
from django.test import TestCase

# Create your tests here.
from django.contrib.auth.models import User
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .serializers import UserSerializer

@api_view(['GET'])
def get_users(request):
    users = User.objects.all()  # Fetch all users
    serializer = UserSerializer(users, many=True)
    return Response(serializer.data)


# ######################################
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.urls import reverse
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from itsdangerous import URLSafeTimedSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import status
from django.shortcuts import render
from django.http import HttpResponse
from itsdangerous.exc import BadSignature, SignatureExpired

# Serializer for generating tokens
serializer = URLSafeTimedSerializer(settings.SECRET_KEY)

class RequestPasswordReset(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")

        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist"}, status=status.HTTP_404_NOT_FOUND)

        # Generate a secure token
        token = serializer.dumps(email, salt="password-reset")

        # Create a password reset link
        reset_url = request.build_absolute_uri(
            reverse("password-reset", kwargs={"token": token})
        )

        # Load the email template and replace variables
        email_body = render_to_string("login.html", {
            "name": user.username,
            "reset_url": reset_url
        })

        # Send the email
        subject = "Reset Your Password"
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [email]

        email_message = EmailMultiAlternatives(subject, "", from_email, recipient_list)
        email_message.attach_alternative(email_body, "text/html")
        email_message.send()

        return Response({"message": "Password reset email sent. Check your inbox."}, status=status.HTTP_200_OK)


class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, token):
        try:
            email = serializer.loads(token, salt="password-reset", max_age=3600)  # Token expires in 1 hour
            user = User.objects.get(email=email)
        except (BadSignature, SignatureExpired, User.DoesNotExist):
            return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

        password = request.data.get("password")
        confirm_password = request.data.get("confirm_password")

        if not password or not confirm_password:
            return Response({"error": "Both fields are required"}, status=status.HTTP_400_BAD_REQUEST)

        if password != confirm_password:
            return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)

        # Save the new password
        user.password = make_password(password)
        user.save()

        return Response({"message": "Password reset successfully. You can now log in."}, status=status.HTTP_200_OK)
    
    
    
#################################################


# from django.contrib.auth.models import User
# from django.contrib.auth.hashers import make_password
# from django.shortcuts import render, redirect
# from django.contrib import messages

# def reset_password(request, user_id):
#     if request.method == "POST":
#         password = request.POST.get("password")
#         confirm_password = request.POST.get("confirm_password")

#         if password != confirm_password:
#             messages.error(request, "Passwords do not match!")
#             return redirect("reset_password", user_id=user_id)

#         try:
#             user = User.objects.get(id=user_id)
#             user.password = make_password(password)  # Hash the new password
#             user.is_active = True  # Activate the user ONLY after password reset
#             user.save()

#             messages.success(request, "Password successfully changed. Your account is now active!")
#             return redirect("login")  # Redirect to login page after reset

#         except User.DoesNotExist:
#             messages.error(request, "User not found!")

#     return render(request, "reset_password.html", {"user_id": user_id})
# from django.contrib.auth.models import User
# from django.contrib.auth.hashers import make_password
# from rest_framework.views import APIView
# from rest_framework.response import Response
# # from rest_framework import status
# from django.views.decorators.csrf import csrf_exempt
# from django.utils.decorators import method_decorator

# @method_decorator(csrf_exempt, name='dispatch')  # Remove this in production
# class ResetPasswordAPIView(APIView):
#     def post(self, request, user_id):
#         try:
#             user = User.objects.get(id=user_id)
#         except User.DoesNotExist:
#             return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

#         password = request.data.get("password")
#         confirm_password = request.data.get("confirm_password")

#         if not password or not confirm_password:
#             return Response({"error": "Both password fields are required"}, status=status.HTTP_400_BAD_REQUEST)

#         if password != confirm_password:
#             return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)

#         # ✅ Reset password and activate user
#         user.password = make_password(password)
#         user.is_active = True  # ✅ Activate user after successful reset
#         user.save()

#         return Response({"message": "Password reset successful. User is now active!"}, status=status.HTTP_200_OK)

# from django.contrib.auth.models import User
# from django.contrib.auth.hashers import make_password
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from django.views.decorators.csrf import csrf_exempt
# from django.utils.decorators import method_decorator

# @method_decorator(csrf_exempt, name='dispatch')  # Remove this in production
# class ResetPasswordAPIView(APIView):
#     def post(self, request, user_id):
#         try:
#             user = User.objects.get(id=user_id)
#         except User.DoesNotExist:
#             return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

#         password = request.data.get("password")
#         confirm_password = request.data.get("confirm_password")

#         if password != confirm_password:
#             return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)

#         # Before password reset, ensure is_active is False
#         if user.is_active:
#             user.is_active = False  
#             user.save()

#         # Reset password
#         user.password = make_password(password)
#         user.is_active = True  # Activate the user after successful reset
#         user.save()

#         return Response({"message": "Password reset successful. User is now active!"}, status=status.HTTP_200_OK)

# from django.views.decorators.csrf import csrf_exempt
# from django.utils.decorators import method_decorator
# from django.http import JsonResponse
# from django.contrib.auth.models import User
# from django.contrib.auth.hashers import make_password
# from rest_framework.views import APIView

# @method_decorator(csrf_exempt, name='dispatch')
# class ResetPasswordAPIView(APIView):
#     def post(self, request, user_id):
#         try:
#             user = User.objects.get(id=user_id)
#         except User.DoesNotExist:
#             return JsonResponse({"error": "User not found"}, status=404)

#         password = request.POST.get("password")
#         confirm_password = request.POST.get("confirm_password")

#         if password != confirm_password:
#             return JsonResponse({"error": "Passwords do not match"}, status=400)

#         user.password = make_password(password)
#         user.is_active = True  # Activate user
#         user.save()

#         return JsonResponse({"message": "Password reset successful. User is now active!"})

# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from django.contrib.auth.models import User
# from .serializers import ResetPasswordSerializer
# @csrf_exempt
# class ResetPasswordAPIView(APIView):
#     def post(self, request, user_id):
#         try:
#             user = User.objects.get(id=user_id)
#         except User.DoesNotExist:
#             return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

#         serializer = ResetPasswordSerializer(user, data=request.data, partial=True)
#         if serializer.is_valid():
#             serializer.save()
#             return Response({"message": "Password reset successful. User is now active!"}, status=status.HTTP_200_OK)
        
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# from django.contrib.auth.models import User
# from django.contrib.auth.hashers import make_password
# from django.shortcuts import render, redirect
# from django.contrib import messages

# def reset_password(request, user_id):
#     if request.method == "POST":
#         password = request.POST.get("password")
#         confirm_password = request.POST.get("confirm_password")
        
#         if password != confirm_password:
#             messages.error(request, "Passwords do not match!")
#             return redirect("reset_password", user_id=user_id)
        
#         try:
#             user = User.objects.get(id=user_id)
#             user.password = make_password(password)  # Hash the password
#             user.is_active = True  # Activate the user
#             user.save()
            
#             messages.success(request, "Password successfully changed and account activated!")
#             return redirect("login")  # Redirect to login page after reset
#         except User.DoesNotExist:
#             messages.error(request, "User not found!")
    
#     return render(request, "reset_password.html", {"user_id": user_id})

# from django.contrib.auth.models import User

# # Set all users to inactive before reset
# User.objects.all().update(is_active=False)

# print("Updated all users to inactive.")