from django.urls import path
from authentication import views

urlpatterns = [
    path('register', views.RegisterAPI.as_view(), name='register-api'),
    path('login', views.LoginAPI.as_view(), name='login-api'),
    path('logout', views.LogOutAPI.as_view(), name='logout-api'),
]