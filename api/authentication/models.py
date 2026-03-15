from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.urls import reverse
from django.db import models
import uuid
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import UserManager as DjangoUserManager


class UserManager(DjangoUserManager):
    def _create_user(self, email: str, password: str or None, **extra_fields):
        if not email:
            raise ValueError("The given email must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.password = make_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email: str, password: str or None = None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email: str, password: str or None = None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self._create_user(email, password, **extra_fields)

class UserModel(AbstractUser):
    email       = models.EmailField(_("email address"), unique=True, db_index=True)
    username    = None
    name        = None
    first_name  = models.CharField(_("First Name"), max_length=255, blank=True, null=True)
    last_name   = models.CharField(_("Last Name"), max_length=255, blank=True, null=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ['first_name','last_name']

    objects = UserManager()

    def get_absolute_url(self) -> str:
        return reverse("users:detail", kwargs={"pk": self.id})
    
    def __str__(self):
        return str(f"{self.email}")
    
    @property
    def full_name(self):
        return f'{self.first_name} {self.last_name}'
    full_name.fget.short_description = 'Full name'

    @property
    def initial_profile(self):
        self.first_name = self.first_name[0] if self.first_name else ''
        self.last_name = self.last_name[0] if self.last_name else ''
        return f'{self.first_name}{self.last_name}'
    initial_profile.fget.short_description = 'Initial Profile'

    def get_full_name(self):
        return self.full_name
    
    def get_initial_profile(self):
        return self.initial_profile
    
    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
