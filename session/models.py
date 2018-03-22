from django.db import models
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser
)


class MyUserManager(BaseUserManager):
    def create_user(self, public_key, jump_code):
        """
        Creates and saves a User
        """
        if not public_key:
            raise ValueError('Users must have a key')

        user = self.model(
            public_key=public_key,
            jump_code=jump_code,
            is_compromised=False
        )
        user.set_unusable_password()
        user.save(using=self._db)
        return user


class MyUser(AbstractBaseUser):
    public_key = models.CharField(
        verbose_name='public key',
        max_length=1023,
        unique=True,
        primary_key=True,
        )
    jump_code = models.CharField(
        verbose_name='jump code',
        max_length=256,
        unique=False,
        primary_key=False,
        )
    is_compromised = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    objects = MyUserManager()

    USERNAME_FIELD = 'public_key'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.public_key

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True


    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True
