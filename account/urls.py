from django.urls import path, include, re_path
from account.views import UserRegistrationView, UserLoginView, UserProfileView, UserChangePasswordView, \
    SendPasswordResetEmailView, UserPasswordResetView, VerifyOtp, DeleteUserView, CustomTokenObtainPairView, \
    CustomTokenRefreshView, TOTPCreateView, TOTPVerifyView, LogoutView, DeleteBlacklistAdOutstandingView
   ##  ResetPasswordView, ActivationConfirm, ForgotPasswordEmailSendView, ForgotPasswordEmailVerifyView,
from rest_framework_simplejwt.views import TokenVerifyView ## TokenObtainPairView, TokenRefreshView,


urlpatterns = [
    # path('gettoken/',TokenObtainPairView.as_view(), name= 'token_pair'),
    # path('refreshtoken/', TokenRefreshView.as_view(), name= 'token_resfresh'),
    path('gettoken/',CustomTokenObtainPairView.as_view(), name= 'token_pair'),
    path('refreshtoken/', CustomTokenRefreshView.as_view(), name= 'token_resfresh'),
    path('verifytoken/',TokenVerifyView.as_view(), name= 'token_verify'),
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name= 'login'),
    path('verify/', VerifyOtp.as_view(), name= 'verify'),
    path('profile/', UserProfileView.as_view(), name= 'profile'),
    path('changepassword/', UserChangePasswordView.as_view(), name= 'changepassword'),
    path('send_reset_password_email/', SendPasswordResetEmailView.as_view(), name= 'send_reset_password_email'),
    path('reset_password/', UserPasswordResetView.as_view(), name= 'reset_password'),
    path('deleteuser/<str:fullName>/', DeleteUserView.as_view(), name= 'deleteuser'),
    path('logout/', LogoutView.as_view(), name= 'logout'),
    path('deletetoken/', DeleteBlacklistAdOutstandingView.as_view(), name= 'deletetoken'),
    re_path(r'^totp/create/$', TOTPCreateView.as_view(), name='totp-create'),
    re_path(r'^totp/login/(?P<token>[0-9]{6})/$', TOTPVerifyView.as_view(), name='totp-login'),
    # path('activate/', ActivationConfirm.as_view(), name='activate'),
    # path('activate/<str:uid>/<str:token>/', ActivationConfirm.as_view(), name='activate'),
    # path('forgotpass/', ForgotPasswordEmailSendView.as_view(), name='forgotpass'),
    # path('forgot_verify/<str:uid>/<str:token>/', ForgotPasswordEmailVerifyView.as_view(), name='forgot_verify'),
    # path('reset/', ResetPasswordView.as_view(), name='reset'),
]

