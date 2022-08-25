from django.urls import path
from authentication import views

urlpatterns = [
    path('register', views.RegisterAPI.as_view(), name='register-api'),
    path('confirmation', views.ConfirmEmailAPI.as_view(), name='email-confrimation-api'),
    path('login', views.LoginAPI.as_view(), name='login-api'),
    path('logout', views.LogOutAPI.as_view(), name='logout-api'),
    path('password/change', views.ChangePasswordAPI.as_view(), name='change-password-api'),
    path('password/reset', views.RequestPasswordResetEmailAPI.as_view(), name='reset-password-api'),
    path('password/set/<token>', views.SetNewPasswordAPI.as_view(), name='set-password-api'),
]