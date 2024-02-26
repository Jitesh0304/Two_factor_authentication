from django.contrib import admin
from account.models import User
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from rest_framework_simplejwt.token_blacklist.admin import OutstandingTokenAdmin



class UserModelAdmin(BaseUserAdmin):
    # form = UserChangeForm
    # add_form = UserCreationForm


    ## diplay list
    list_display = ('email', 'fullName', 'otp','is_verified','two_factor_enable', 'created_at','last_login','is_superuser',
                    'qr_image_url',)
    ## filter list
    list_filter = ('is_verified', 'two_factor_enable')
    ## admin page user create option
    fieldsets = (
        ('User Credentials', {'fields': ('email', 'password','fullName','is_verified',)}),
        ('User security', {'fields': ('two_factor_enable', )}),
        ('Django Permissions', {'fields': ('is_superuser',)}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'fullName','password1', 'password2','is_verified', 'two_factor_enable',),
        }),
    )
    ## search option
    search_fields = ('email',)
    ## order by
    ordering = ('email','created_at')
    filter_horizontal = ()

admin.site.register(User, UserModelAdmin)



class CustomOutstandingTokenAdmin(OutstandingTokenAdmin):
    list_display = (
        "id",
        "jti",
        "user",
        "created_at",
        "expires_at",
    )
    def has_delete_permission(self, request, obj=None) -> bool:
        if request.user.is_superuser:
            return True
        return False

admin.site.unregister(OutstandingToken)
admin.site.register(OutstandingToken, CustomOutstandingTokenAdmin)





# from django import forms
# from django.contrib.auth.models import Group
# from django.contrib.auth.forms import ReadOnlyPasswordHashField
# from django.core.exceptions import ValidationError

# class UserCreationForm(forms.ModelForm):
#     """A form for creating new users. Includes all the required
#     fields, plus a repeated password."""

#     password1 = forms.CharField(label="Password", widget=forms.PasswordInput)
#     password2 = forms.CharField(
#         label="Password confirmation", widget=forms.PasswordInput
#     )

#     class Meta:
#         model = User
#         fields = ["email", "password1"]

#     def clean_password2(self):
#         # Check that the two password entries match
#         password1 = self.cleaned_data.get("password1")
#         password2 = self.cleaned_data.get("password2")
#         if password1 and password2 and password1 != password2:
#             raise ValidationError("Passwords don't match")
#         return password2

#     def save(self, commit=True):
#         # Save the provided password in hashed format
#         user = super().save(commit=False)
#         user.set_password(self.cleaned_data["password1"])
#         if commit:
#             user.save()
#         return user


# class UserChangeForm(forms.ModelForm):
#     """A form for updating users. Includes all the fields on the user, but replaces the password field with admin's
#     disabled password hash display field.
#     """
#     password = ReadOnlyPasswordHashField()

#     class Meta:
#         model = User
#         fields = ["email", "password", "fullName", "is_verified", "two_factor_enable","is_superuser"]

