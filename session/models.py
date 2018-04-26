from django.db import models
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser
)
import logging
from crypto.helpers import full_hash

class MyUserManager(BaseUserManager):
    def create_user(self, email_hash, public_key, jump_code, length):
        """
        Creates and saves a User
        """
        if not public_key:
            raise ValueError('Users must have a key')

        try:
            return MyUser.objects.get(pk=full_hash(public_key))
        except MyUser.DoesNotExist:
            logging.debug("create user")
            logging.debug(email_hash)
            logging.debug(public_key)
            logging.debug(str(full_hash(public_key)))
            logging.debug(jump_code)
            user = self.model(
                public_key_hash=full_hash(public_key),
                email_hash=email_hash,
                public_key=public_key,
                jump_code=jump_code,
                length=length,
                is_compromised=False
            )
            user.set_unusable_password()
            user.save(using=self._db)
            logging.debug("user created %s", user.email_hash)
            return user


class MyUser(AbstractBaseUser):
    public_key_hash = models.BigIntegerField(
        verbose_name='public key_hash',
        unique=True,
        primary_key=True,
        )
    public_key = models.CharField(
        verbose_name='public key',
        max_length = 5000,
        unique=True,
        )
    email_hash = models.BigIntegerField(
        verbose_name='email hash',
        unique=True,
        default=None,
        )
    user_data = models.BinaryField(
        verbose_name='user data',
        default=None,
        blank=True,
        null=True,
        )
    recovery_data = models.BinaryField(
        verbose_name='data for recover lost key',
        default=None,
        blank=True,
        null=True,
        )
    jump_code = models.BigIntegerField(
        verbose_name='jump code',
        unique=False,
        )
    key_length = models.BigIntegerField(
        verbose_name='length of private key',
        unique=False,
        default=0,
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
