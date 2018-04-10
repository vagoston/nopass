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

        try:
            return MyUser.objects.get(pk=public_key)
        except MyUser.DoesNotExist:
            user = self.model(
                public_key=public_key,
                jump_code=jump_code,
                is_compromised=False
            )
            user.set_unusable_password()
            user.save(using=self._db)
            return user


class MyUser(AbstractBaseUser):
    public_key_hash = models.CharField(
        verbose_name='public key_hash',
        max_length=256,
        unique=True,
        primary_key=True,
        )
    public_key = models.BinaryField(
        verbose_name='public key',
        unique=True,
        )
    email_hash = models.CharField(
        verbose_name='email hash',
        max_length=256,
        unique=True,
        default=None
        )
    user_data = models.BinaryField(
        verbose_name='user data',
        default=None
        )
    recovery_data = models.BinaryField(
        verbose_name='data for recover lost key',
        default=None,
        )
    jump_code = models.BigIntegerField(
        verbose_name='jump code',
        unique=False,
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
