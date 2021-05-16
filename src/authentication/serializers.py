from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.hashers import make_password
from django.contrib.auth import password_validation

from django.core.exceptions import ValidationError
from rest_framework import serializers

from .models import Users


User=get_user_model()



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


def get_and_authenticate_user(email, password):
    user = authenticate(email=email, password=password)
    if user is None:
        raise serializers.ValidationError({"error": "Invalid username or password"})
    return user
    
def validate_password(value):
    try:
        password_validation.validate_password(value)
    except ValidationError as error:
        raise serializers.ValidationError({'error':'Password must contain at least 8 charachters'})
    return value
