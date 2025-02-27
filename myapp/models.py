from django.db import models
from django.contrib.auth.models import AbstractUser,BaseUserManager
from myapp.utils import STATUS_CHOICES, ROLE_TYPE


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

