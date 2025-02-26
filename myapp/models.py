from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from .utils import (USER_STATUS,USER_TYPE,ROLE_STATUS,ROLE_STATUS_DETAILS,ROLE_TYPE)

class Role(models.Model):
    ROLE_CHOICES = [
        (1, 'Admin'),
        (2, 'Teacher'),
        (3, 'Student'),
    ]
    id = models.IntegerField(choices=ROLE_CHOICES, primary_key=True)  # Fix IDs to 1, 2, 3
    name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.name
    
    
class User(AbstractUser):
    
    
    
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)
    
    groups = models.ManyToManyField(
        "auth.Group",
        related_name="custom_user_set",
        blank=True,
        help_text="The groups this user belongs to.",
    )
    user_permissions = models.ManyToManyField(
        "auth.Permission",
        related_name="custom_user_permissions_set",
        blank=True,
        help_text="Specific permissions for this user.",
    )
    
from django.db import models
from django.contrib.auth.models import User

class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    image = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True)
    def __str__(self):
        return f"{self.user.username} - {self.role.name}"
