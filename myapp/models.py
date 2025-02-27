from django.db import models
from django.contrib.auth.models import AbstractUser,BaseUserManager
from myapp.utils import STATUS_CHOICES, STATUS_PENDING


class StudentManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        extra_fields.setdefault("is_active", True)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(email, password, **extra_fields)


# Role Model
class Role(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name


# Custom User Model (Student)
class Student(AbstractUser):
    username = None  # Remove username field
    name = models.CharField(max_length=200)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=225)
    role = models.ForeignKey("Role", on_delete=models.SET_NULL, null=True, blank=True)
    image = models.ImageField(upload_to="profile_pics/", null=True, blank=True)

    objects = StudentManager()  # Use custom manager

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name"]

    def __str__(self):
        return self.email
    
    
    
class Profile(models.Model):
    user = models.OneToOneField("myapp.Student", on_delete=models.CASCADE)  # Reference custom user model
    image = models.ImageField(upload_to="profile_pics/", null=True, blank=True)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

# from django.db import models
# from django.contrib.auth.models import BaseUserManager, AbstractBaseUser

# class StudentManager(BaseUserManager):
#     """Custom manager for Student model."""

#     def create_user(self, email, name, password=None, **extra_fields):
#         if not email:
#             raise ValueError("The Email field must be set")
#         email = self.normalize_email(email)
#         user = self.model(email=email, name=name, **extra_fields)
#         user.set_password(password)  # Hash password before saving
#         user.save(using=self._db)
#         return user

#     def create_superuser(self, email, name, password=None, **extra_fields):
#         """Create and return a superuser."""
#         extra_fields.setdefault("is_admin", True)
#         extra_fields.setdefault("is_staff", True)

#         return self.create_user(email, name, password, **extra_fields)

# class Student(AbstractBaseUser):
#     """Custom user model without Django defaults."""
    
#     email = models.EmailField(unique=True)
#     name = models.CharField(max_length=200)
#     password = models.CharField(max_length=225)
#     role = models.ForeignKey("myapp.Role", on_delete=models.CASCADE, null=True, blank=True)
#     image = models.ImageField(upload_to='profile_pics/', null=True, blank=True)

#     is_active = models.BooleanField(default=True)
#     is_admin = models.BooleanField(default=False)
#     is_staff = models.BooleanField(default=False)

#     USERNAME_FIELD = 'email'
#     REQUIRED_FIELDS = ['name']

#     objects = StudentManager()  # ✅ Use custom manager

#     def __str__(self):
#         return self.email


# class Role(models.Model):
#     id = models.AutoField(primary_key=True)  # Explicitly add auto-incrementing ID
#     name = models.CharField(max_length=100)

#     def __str__(self):
#         return self.name

# class Student(AbstractUser):
#     username = None  # ✅ Remove the username field from AbstractUser
#     name = models.CharField(max_length=200)
#     email = models.EmailField(unique=True)
#     password = models.CharField(max_length=225, default='default_password')
#     role = models.ForeignKey(Role, on_delete=models.CASCADE, null=True, blank=True)  # ✅ Allow blank roles
#     image = models.ImageField(upload_to='profile_pics/', null=True, blank=True)  # ✅ Allow profile image

#     USERNAME_FIELD = 'email'
#     REQUIRED_FIELDS = ["name"]  # ✅ Required fields for createsuperuser

#     def __str__(self):
#         return self.email

# class Profile(models.Model):
#     user = models.OneToOneField(Student, on_delete=models.CASCADE)  # ✅ Link Profile to Student
#     image = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
#     role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True)  # ✅ Allow null roles

#     def __str__(self):
#         return f"{self.user.email} - {self.role.name if self.role else 'No Role'}"

# # from django.db import models
# # from django.contrib.auth.models import AbstractUser
# # from django.conf import settings
# # from .utils import (USER_STATUS,USER_TYPE,ROLE_STATUS,ROLE_STATUS_DETAILS,ROLE_TYPE)

# # class Role(models.Model):
# #     ROLE_CHOICES = [
# #         (1, 'Admin'),
# #         (2, 'Teacher'),
# #         (3, 'Student'),
# #     ]
# #     id = models.IntegerField(choices=ROLE_CHOICES, primary_key=True)  # Fix IDs to 1, 2, 3
# #     name = models.CharField(max_length=50, unique=True)

# #     def __str__(self):
# #         return self.name
    
    
# # from django.db import models
# # from rest_framework.views import APIView
# # from rest_framework.response import Response
# # from rest_framework.permissions import IsAuthenticated
# # from rest_framework import status
# # from django.contrib.auth.models import AbstractUser
# # class Admin(models.Model):
# #     name = models.CharField(max_length=100)
# #     roleid=models.CharField(max_length=3,null= True)
    
# #     def __str__(self):
# #         return f"{self.name}{self.role}"
        
# # # class Role(models.Model):
# # #     id = models.AutoField(primary_key=True) 
# # #     name = models.CharField(max_length=200, unique=True)
    
# # #     def __str__(self):
# # #         return self.name
    
# # class Student(AbstractUser):  # Extend AbstractUser
# #     name=models.CharField(max_length=200)
# #     email=models.EmailField(unique=True)
# #     password=models.CharField(max_length=225,default='default_password')
# #     Role=models.ForeignKey(Role, on_delete=models.CASCADE,null=True)
# #         image = models.ImageField(upload_to='profile_pics/', null=True, blank=True)

    
    
# #     username = None  # Disable the username field

# #     USERNAME_FIELD = 'email'  # Use email for authentication
# #     REQUIRED_FIELDS = []  # Fields required when creating a superuser

# #     def __str__(self):
# #         return self.email
    
# # # class Student(AbstractUser):
    
    
    
# # #     role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)
    
# # #     groups = models.ManyToManyField(
# # #         "auth.Group",
# # #         related_name="custom_user_set",
# # #         blank=True,
# # #         help_text="The groups this user belongs to.",
# # #     )
# # #     user_permissions = models.ManyToManyField(
# # #         "auth.Permission",
# # #         related_name="custom_user_permissions_set",
# # #         blank=True,
# # #         help_text="Specific permissions for this user.",
# # #     )
    
# # from django.db import models

# # class Profile(models.Model):
# #     user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
# #     image = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
# #     # role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True)
# #     def __str__(self):
# #         return f"{self.user.username} - {self.role.name}"
# from django.db import models
# from django.contrib.auth.models import AbstractUser
# from myapp.utils import STATUS_CHOICES, STATUS_PENDING


# class Role(models.Model):
#         id = models.AutoField(primary_key=True)  # Explicitly add auto-incrementing ID
#         name = models.CharField(max_length=100)

#         def __str__(self):
#          return self.name

# class Student(AbstractUser):
#     name = models.CharField(max_length=200)
#     email = models.EmailField(unique=True)
#     password = models.CharField(max_length=225, default='default_password')
#     role = models.ForeignKey(Role, on_delete=models.CASCADE, null=True)  # ✅ Fixed Capitalization
#     image = models.ImageField(upload_to='profile_pics/', null=True, blank=True)  # ✅ Ensure this exists

    

#     # username = None  # Disable the username field
    
#     USERNAME_FIELD = 'email'
#     REQUIRED_FIELDS = ["name"]

#     def __str__(self):
#         return self.email

# class Profile(models.Model):
#     user = models.OneToOneField(Student, on_delete=models.CASCADE)  # ✅ Ensure it's linked to Student
#     image = models.ImageField(upload_to='profile_pics/', null=True, blank=True)  # ✅ Ensure this exists
#     role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True)  # ✅ Ensure this exists

#     def __str__(self):
#         return f"{self.user.email} - {self.role.name if self.role else 'No Role'}"
