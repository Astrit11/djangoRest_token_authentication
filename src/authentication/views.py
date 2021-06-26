
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.http import JsonResponse

from utils.utils import confirm_email, forgot_password
from .token_expiration import token_expire_handler, expires_in      
from rest_framework.authtoken.models import Token


from rest_framework import permissions
from rest_framework.authtoken.views import APIView

from .models import Users

from .serializers import (
    RegisterSerializer,
    EmailConfirmationSerializer,
    LoginSerializer,
    PasswordChangeSerializer,
    ResetPasswordEmailRequestSerializer,
    PasswordResetSerializer,
    get_and_authenticate_user,
    validate_password,
)


User = get_user_model()

'''
  A class for registering users
'''


class RegisterAPI(APIView):
    def post(self, request):
        if 'is_staff' in request.data and request.data['is_staff'] or 'is_superuser' in request.data and request.data['is_superuser']:
            return JsonResponse({'status': False, 'msg': 'Unautorized request', 'data': {}}, status=200)
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            validate_password(value=request.data.get("password"))
            user = serializer.save()
            if user:
                token = user.email_verification_token = PasswordResetTokenGenerator().make_token(user)
                # confirm_email(token=token, user=user)
                data = {
                    'firstName': user.first_name,
                    'lastName': user.last_name,
                    'token': user.auth_token.key,
                    'email': user.email,
                    'email_verification_token': user.email_verification_token,
                }
                user.save(update_fields=["email_verification_token"])
                return JsonResponse({'status': True, 'msg': 'Succesfully created user', 'data': data}, status=200)
        return JsonResponse({'status': False, 'msg': 'Could not create user', 'data': {}}, status=200)


class ConfirmEmailAPI(APIView):
    def post(self, request):
        try:
            token = request.data.get('email_verification_token')
            user = Users.objects.get(email_verification_token=token)
            if user:
                if PasswordResetTokenGenerator().check_token(user, token):
                    serializer = EmailConfirmationSerializer(
                        user, data=request.data)
                    if serializer.is_valid():
                        user.is_confirmed = True
                        user.created = True
                        serializer.save()
                        return JsonResponse({'status': True, 'msg': 'Email confirmed successfully', 'data': {}}, status=200)
                    return JsonResponse({'status': False, 'msg': 'Could not confirm email', 'data': {}}, status=401)
                return JsonResponse({'status': False, 'msg': 'This user does not exist', 'data': {}}, status=401)
            return JsonResponse({'status': False, 'msg': 'This user does not exist', 'data': {}}, status=401)
        except Users.DoesNotExist:
            return JsonResponse({'status': False, 'msg': 'Internal system error', 'data': {}}, status=500)


'''
  A class for login user
'''


class LoginAPI(APIView):
    def post(self, request):
        try:
            serializer = LoginSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                user = get_and_authenticate_user(**serializer.validated_data)
                if user:
                    token, _ = Token.objects.get_or_create(user = user)
                    is_expired, token = token_expire_handler(token)
                    data = {
                        'userId': user.pk,
                        'firstName': user.first_name,
                        'lastName': user.last_name,
                        'email': user.email,
                        'token': token.key,
                        'expires_in': expires_in(token),
                    }   
                    return JsonResponse({'status': True, 'msg': 'Succesfully logged in user', 'data': data}, status=200)
            return JsonResponse({'status': False, 'msg': 'You must confirm youre email address in order to continue ', 'data': {}}, status=200)
        except Users.DoesNotExist:
            return JsonResponse({'status': False, 'msg': 'Internal system error', 'data': {}}, status=500)


'''
  A class for logging out user
'''


class LogOutAPI(APIView):
    permission_classes = [permissions.IsAuthenticated, ]

    def post(self, request):
        try:
            request.user.auth_token.delete()
        except (AttributeError):
            return JsonResponse({'status': False, 'msg': 'User can not be logged out at the moment', "data": {}}, status=400)
        return JsonResponse({'status': True, 'msg': 'Successfully logged out', "data": {}}, status=200)


'''
  A class for changing the user password
'''


class ChangePasswordAPI(APIView):
    """
    An endpoint for changing password.
    """
    permission_classes = (permissions.IsAuthenticated, )

    def put(self, request):
        try:
            self.object = self.request.user
            serializer = PasswordChangeSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                validate_password(value=request.data.get("new_password"))
                old_password = serializer.data.get("old_password")
                if not self.object.check_password(old_password):
                    return JsonResponse({'status': False, 'msg': 'Wrong password provided', 'data': {}}, status=400)
                self.object.set_password(serializer.data.get("new_password"))
                self.object.save()
                return JsonResponse({'status': True, 'msg': 'Succesfully updated password'})
            return JsonResponse({'status': False, 'msg': 'Can not change password'}, status=400)
        except Users.DoesNotExist:
            return JsonResponse({'status': False, 'msg': 'Internal system error', 'data': {}}, status=500)


class RequestPasswordResetEmailAPI(APIView):
    def post(self, request):
        try:
            self.object = self.request.user
            serializer = ResetPasswordEmailRequestSerializer(data=request.data)
            if serializer.is_valid():
                user = serializer.validated_data
                user.email_token = PasswordResetTokenGenerator().make_token(user)
                forgot_password(user.email_token, user)
                user.save(update_fields=["email_token"])
                return JsonResponse({'status': True, 'msg': 'We have sent you a link to reset your password!', 'data': user.email_token}, status=200)
            return JsonResponse({'status': False, 'msg': 'No registered user with this email!', 'data': {}}, status=400)
        except Users.DoesNotExist:
            return JsonResponse({'status': False, 'msg': 'Internal system error', 'data': {}}, status=500)


class SetNewPasswordAPI(APIView):
    def put(self, request, token):
        try:
            self.object = self.request.user
            client = User.objects.get(email_token=token)
            if client:
                if PasswordResetTokenGenerator().check_token(client, token):
                    serializer = PasswordResetSerializer(
                        client, data=request.data)
                    if serializer.is_valid(raise_exception=True):
                        validate_password(value=request.data.get("password"))
                        user = serializer.save()
                        user.set_password(serializer.data.get("password"))
                        user.save(update_fields=["password"])
                        return JsonResponse({'status': True, 'msg': 'Password changed successfully', 'data': {}}, status=200)
                    return JsonResponse({'status': False, 'msg': 'Could not reset password', 'data': {}}, status=401)
                return JsonResponse({'status': False, 'msg': 'Token is not valid', 'data': {}}, status=401)
            return JsonResponse({'status': False, 'msg': 'This user does not exist', 'data': {}}, status=401)
        except Users.DoesNotExist:
            return JsonResponse({'status': False, 'msg': 'Internal system error', 'data': {}}, status=500)
