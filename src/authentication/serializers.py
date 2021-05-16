from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from rest_framework import serializers

from .models import Users

User=get_user_model()

def get_and_authenticate_user(email, password):
    user = authenticate(email=email, password=password)
    if user is None:
        raise serializers.ValidationError({"error": "Invalid username or password"})
    return user
    
class UsersSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ('id', 'first_name', 'last_name','email', 'is_confirmed',)

        
class RegisterSerializer(serializers.ModelSerializer):
    """
    Serializer for registering users endpoint.
    """
    class Meta:
        model = Users
        fields = ('id', 'first_name', 'last_name', 'email','password')
        extra_kwargs = {'password': {'write_only': True}}    

    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data['password'])
        client = Users.objects.create(**validated_data)
        return client
    
    def validate_password(self, value):
        try:
            validate_password(value)
        except ValidationError:
            raise serializers.ValidationError('Password must contain at least 9 carachters')
        return value

class LoginSerializer(serializers.Serializer):
    """
    Serializer for login endpoint.
    """
    email = serializers.CharField(max_length=300, required=True)
    password = serializers.CharField(required=True, write_only=True)


class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer for password change endpoint.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_password(self, value):
        try:
            validate_password(value)
        except ValidationError:
            raise serializers.ValidationError('Password must contain at least 9 carachters')
        return value

class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ('email',)

    def validate(self, attrs):
        email = attrs.get('email')
        user = User.objects.get(email=email)
        if user is None:
            raise serializers.ValidationError({"error":"A user with this email is not found."})
        return user
        
class EmailConfirmationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('email_verification_token',)

class PasswordResetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ('password',)

    # def update(self, instance, validated_data):
    #     password = validated_data.get('password', instance.password)
    #     instance.set_password(password)
    #     instance.save()
    #     return instance

    def update(self, instance, validated_data):
        instance.password = validated_data.get('password', instance.password)
        instance.save()
        return instance 

    def validate_password(self, password):
        try:
            validate_password(password)
        except ValidationError:
            raise serializers.ValidationError('Password must contain at least 9 carachters.')
        return password