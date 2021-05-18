from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.models import Group

from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token


class UserManager(BaseUserManager):
    """Define a model manager for User model with no username field."""

    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        """Create and save a User with the given email and password."""
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        """Create and save a regular User with the given email and password."""
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        """Create and save a SuperUser with the given email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)

    def get_groups(self,name):
        try:
            return Group.objects.filter(name=name)
        except Group.DoesNotExist:
            return None

    def get_users_in_group(self,name):
        return Users.objects.filter(groups__name=name)
    
    def _create_manager(self,email,password,**extra_fields):
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        manager = self.model(email=email, **extra_fields)
        manager.set_password(password)
        manager_group = Group.objects.get(name='Manager') 
        manager_group.user_set.add(manager)
        manager.save(using=self._db)
        return manager

    def create_manager(self, email, password=None, **extra_fields):
        """Create and save a staff Manager with the given email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    @receiver(post_save, sender=settings.AUTH_USER_MODEL)
    def create_auth_token(sender, instance=None, created=False, **kwargs):
        if created:
            token = Token.objects.create(user=instance)
            return token

class Users(AbstractUser):
    username = None
    email = models.EmailField(verbose_name='email address', max_length=100, unique=True)
    email_token = models.CharField(verbose_name='email_token', max_length=300,null=True,blank=True)
    is_confirmed = models.BooleanField(verbose_name='is_confirmed', null=True)
    email_verification_token = models.CharField(verbose_name='email_verification_token', max_length=300, null=True,blank=True)
    
    USERNAME_FIELD='email'
    REQUIRED_FIELDS=[]

    objects = UserManager()

    class Meta:
        db_table = "Users"
        verbose_name_plural = "Users"

  
