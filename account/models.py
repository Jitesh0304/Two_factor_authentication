from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin
from django.utils import timezone



class UserManager(BaseUserManager):
    def create_user(self, email, fullName, two_factor_enable, password=None,otp =None, password2 = None):
        """
        Creates and saves a User with the given email, name ,
        otp  and password.
        """
        if not email:
            raise ValueError('Users must have an email address')
        if not fullName:
            raise ValueError('Users must provide his full name')

        user = self.model(
            email = self.normalize_email(email),
            fullName = fullName,
            otp = otp,
            two_factor_enable= two_factor_enable
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, fullName, otp=None, password=None):
        """
        Creates and saves a superuser with the given email, name,
        tc and password.
        """
        user = self.create_user(
            email,
            password = password,
            fullName = fullName,
            otp = otp,
            two_factor_enable= False
        )
        user.is_superuser = True
        user.is_verified = True
        user.created_at = timezone.now()
        user.save(using=self._db)
        return user


class User(AbstractBaseUser,PermissionsMixin):
    email = models.EmailField(
        primary_key=True,
        verbose_name='Email',
        max_length=255
    )

    fullName = models.CharField(max_length=100, unique=True)
    otp = models.CharField(max_length=6, null=True, blank=True, default="")
    created_at = models.DateTimeField(null=True, blank=True)
    last_login = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default= False)
    is_superuser = models.BooleanField(default=False)
    two_factor_enable = models.BooleanField(default=False)
    qr_image_url = models.CharField(max_length=200, null=True, blank=True)
    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['fullName']


    # class Meta:
    #     permissions = (
    #         ("can_view_dashboard", "Can view dashboard"),
    #         ("can_edit_profile", "Can edit profile"),
    #     )


    def __str__(self):
        return self.fullName

    # def get_full_name(self):
    #     return self.fullName
    

    # def has_perm(self, perm, obj=None):
    #     "Does the user have a specific permission?"
    #     # Simplest possible answer: Yes, always
    #     return self.is_superuser


    # def has_module_perms(self, app_label):
    #     "Does the user have permissions to view the app `app_label`?"
    #     # Simplest possible answer: Yes, always
    #     return True

    # @property
    # def is_staff(self):
    #     "Is the user a member of staff?"
    #     # Simplest possible answer: All admins are staff
    #     return self.is_superuser



    def has_perm(self, perm, obj=None):
        # Custom logic: superusers have all permissions
        if self.is_superuser:
            return True

        # Custom logic: check if user is in a specific group
        if self.groups.filter(name='SpecialGroup').exists():
            return True

        # Default permission checking
        return super().has_perm(perm, obj)


    def has_module_perms(self, app_label):
        # Custom logic: superusers have permissions for any module
        if self.is_superuser:
            return True

        # Custom logic: allow access to specific modules for users in certain groups
        allowed_groups = ['SpecialGroup', 'AnotherGroup']
        if self.groups.filter(name__in=allowed_groups).exists():
            return True

        # Default module permission checking
        return super().has_module_perms(app_label)


    @property
    def is_staff(self):
        # Custom logic: superusers are always staff
        if self.is_superuser:
            # print(1)
            return True

        if self.two_factor_enable:
            # print(2)
            return True
        # Custom logic: users with custom attribute are staff
        # return self.custom_attribute
        return False
    

