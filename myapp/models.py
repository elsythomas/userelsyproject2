from django.db import models

class Role(models.Model):
    id = models.AutoField(primary_key=True) 
    name = models.CharField(max_length=200, unique=True)
    
    def __str__(self):
        return self.name
    
from django.db import models
from django.contrib.auth.models import User

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    image = models.ImageField(upload_to='profile_pics/', null=True, blank=True)

    
