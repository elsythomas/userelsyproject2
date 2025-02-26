# from django.contrib.auth.models import User
from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from django.contrib.auth import get_user_model
User = get_user_model()  

class ResetPasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["password", "confirm_password"]

    def validate(self, data):
        if data["password"] != data["confirm_password"]:
            raise serializers.ValidationError("Passwords do not match!")
        return data

    def update(self, instance, validated_data):
        instance.password = make_password(validated_data["password"])
        instance.is_active = True  # ✅ Set user as active after reset
        instance.save()
        return instance

    
# from rest_framework import serializers
# from django.contrib.auth.models import User  # Import User model

class UserSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()
    class Meta:
        model = User
        fields = ["id", "username", "email", "status","image"]
        

    def get_status(self, obj):
        return "Active" 
    
    
class BulkUserCreateSerializer(serializers.Serializer):
    file = serializers.FileField()

    def validate_file(self, value):
        """Ensure the uploaded file is an Excel file."""
        print(f"Received file: {value.name}")  # ✅ Debugging
        print(f"File Name: {value.name}")
        if not value.name.endswith(('.xls', '.xlsx')):
            raise serializers.ValidationError("Only Excel files are allowed.")
        return value