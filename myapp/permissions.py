from rest_framework import serializers 
from .models import User, Admin


class LoginSerializer(serializers.ModelSerializer):
    class Meta:
        model= User
        fields = ["email","password"]

class LoginAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model= User
        fields = ["name","email", "Role"]

