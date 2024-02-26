from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer,\
      UserChangePassword, SendPasswordResetEmailSerializer, UserPasswordResetSerializer, VerifyOtpSerializer,\
      CustomTokenObtainPairSerializer, CustomTokenRefreshSerializer, CustomTokenBlacklistSerializer
from django.contrib.auth import authenticate
from .renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from .models import User
from django.shortcuts import render
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from account.utils import sent_otp_by_email, generate_otp_qr_code, get_user_totp_device## , reset_pass_otp_email, send_activation_email, send_forgot_pass_email,
from django.utils import timezone
from django.http import JsonResponse
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from datetime import timedelta
from django_otp import devices_for_user
from django_otp.plugins.otp_totp.models import TOTPDevice
import os
# from rest_framework.pagination import PageNumberPagination
# from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
# from datetime import timedelta

# import logging
# import jwt
# from decouple import config
# from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
# from django.utils.encoding import force_bytes, force_str
# from django.contrib.auth.tokens import default_token_generator
# from django.urls import reverse



# logger = logging.getLogger('main')



# current_dir = os.getcwd()
# if os.path.exists(os.path.join(current_dir, "QR_folder")):
#     pass
# else:
#     os.makedirs(os.path.join(current_dir, "QR_folder"), exist_ok=True)


        ## home page
def homepage(request):
    return render(request, 'account/home.html')

        ## generate token for user
# def get_tokens_for_user(user):
        ## send the user details to RefreshToken.for_user() .. and get the access token and refresh token
#     refreshToken = RefreshToken.for_user(user)
#     accessToken = refreshToken.access_token
#             ## decode the JWT .... mension the same name of th e secrete_key what ever you have written in .env file
#     decodeJTW = jwt.decode(str(accessToken), config('DJANGO_SECRET_KEY'), algorithms=["HS256"])
#             # add payload here!!
#     decodeJTW['user'] = str(user)
#     decodeJTW['fullName'] = str(user.fullName)
#             # encode
#     encoded = jwt.encode(decodeJTW, config('DJANGO_SECRET_KEY'), algorithm="HS256")
#     return {
#         'refresh': str(refreshToken),
#         'access': str(encoded),
#     }


# class CustomTokenObtainPairView(TokenObtainPairView):
#     serializer_class = CustomTokenObtainPairSerializer
            ####### OR ######



def get_user_totp_device(self, user, confirmed=None):
    devices = devices_for_user(user, confirmed=confirmed)
    for device in devices:
        if isinstance(device, TOTPDevice):
            return device


class TOTPCreateView(APIView):
    """
    Use this endpoint to set up a new TOTP device
    """
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        user = request.user
        device = get_user_totp_device(self, user)
        if not device:
            # print('1')
            device = user.totpdevice_set.create(confirmed=False)
            qr_path = generate_otp_qr_code(device.bin_key, user.fullName)
            user.two_factor_enable = True
            user.qr_image_url = qr_path
            user.save()
        # url = device.config_url
        # requied_data = url.split('?secret=')[1]
        # secret_key = requied_data.split('&algorithm=')[0]
        # algorithm = requied_data.split('&algorithm=')[1].split('&digits=')[0]
        # digits = requied_data.split('&algorithm=')[1].split('&digits=')[1].split('&period=')[0]
        # period = requied_data.split('&algorithm=')[1].split('&digits=')[1].split('&period=')[1]
        else:
            # print('2')
            qr_path = user.qr_image_url
        return Response({"msg":"Two factor authentication successfully enable in you account ....",
                         "url":qr_path}, status=status.HTTP_201_CREATED)


class TOTPVerifyView(APIView):
    """
    Use this endpoint to verify/enable a TOTP device
    """
    permission_classes = [IsAuthenticated]
    def post(self, request, token, format=None):
        user = request.user
        device = get_user_totp_device(self, user)
        if not device == None and device.verify_token(token):
            if not device.confirmed:
                device.confirmed = True
                device.save()
            return Response({'msg':'Successful'}, status=status.HTTP_200_OK)
        return Response({'msg':'Error'},status=status.HTTP_400_BAD_REQUEST)




    ## generate new token during login time
class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
        ## send user data by a post request
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                user = serializer.user
                    # Check if the user is verified
            # if not user.is_verified:
            #     return Response({'msg': 'User is not verified'}, status=status.HTTP_400_BAD_REQUEST)
                # user = User.objects.get(email = user)
                    ## take the token from the serializer
                token = serializer.validated_data
                    ## create refresh_token
                # refresh_token = RefreshToken.for_user(user)
                    ## add user details if required
                response_data = {
                    'access': str(token['access']),
                    'refresh': str(token['refresh'])
                }
                user.last_login = timezone.now()
                user.save()
                return Response({"token":response_data}, status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'msg': str(e)}, status=status.HTTP_400_BAD_REQUEST)


        ## regenerate the access token using refresh token
class CustomTokenRefreshView(TokenRefreshView):
    serializer_class = CustomTokenRefreshSerializer
    def post(self, request, *args, **kwargs):               ## use this or not .. you will get result
        data = super().post(request, *args, **kwargs)
        return data



    # create new user 
class UserRegistrationView(APIView):
        ## render the error message using custome render class
    renderer_classes = [UserRenderer]
    def post(self, request, format =None):
        # logger.info('Request for user registration')
        try:
            # host_name = request.META.get('HTTP_HOST', None)
            # print(host_name)
            serializer = UserRegistrationSerializer(data = request.data)
            if serializer.is_valid():

                        ## If a user send some extra fields data.. Then this error will occure
                # input_data = set(serializer.initial_data.keys())
                # required_fields = set(serializer.fields.keys())
                # ext_data =  input_data - required_fields 
                # if ext_data:
                #     return Response({'msg':f"You have provided extra field {ext_data}"}, status.HTTP_400_BAD_REQUEST)
                
                user = serializer.save()
                # print(user)
                user.created_at= timezone.now()
                user.save()
                    ## send account verification otp to user email id
                sent_otp_by_email(serializer.data['email'])
                # uid = urlsafe_base64_encode(force_bytes(user.email))
                # token = default_token_generator.make_token(user)
                # activation_link = reverse('activate', kwargs={'uid': uid, 'token': token})
                # activation_url = f'http://{host_name}{activation_link}'
                # send_activation_email(user.email, activation_url, host_name)
                if user.two_factor_enable:
                    user_data = User.objects.get(email= serializer.data['email'])
                    device = get_user_totp_device(self, user=user_data)
                    if not device:
                        device = user_data.totpdevice_set.create(confirmed=False)
                    
                    # Generate the QR code image
                    img_path = generate_otp_qr_code(device.bin_key, user_data.fullName)
                    user_data.qr_image_url = img_path
                    user_data.save()
                    return Response({'msg': 'Registration Successful...An email has been sent to your Email-ID Verify your account',
                                     'qr_image_path':img_path}, status.HTTP_201_CREATED)
                return Response({'msg': 'Registration Successful...An email has been sent to your Email-ID Verify your account'}, 
                                status.HTTP_201_CREATED)
            return Response({'msg': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            # logger.error(str(e))
            return Response({'msg': str(e)}, status=status.HTTP_400_BAD_REQUEST)





        ## verify OTP 
class VerifyOtp(APIView):

    def post(self, request, format=None):
        try:
            # logger.info('Request for OTP verification')
            data = request.data 
            serializer = VerifyOtpSerializer(data= data)
            if serializer.is_valid():
                        ## If a user send some extra fields data.. Then this error will occure
                # input_data = set(serializer.initial_data.keys())
                # required_fields = set(serializer.fields.keys())
                # ext_data =  input_data - required_fields 
                # if ext_data:
                #     return Response({'msg':f"You have provided extra field {ext_data}"}, status.HTTP_400_BAD_REQUEST)
                email = serializer.data['email']
                otp = serializer.data['otp']
                try:
                    user = User.objects.get(email=email)
                except Exception:
                    return Response({'msg': 'User does not exist with this email..'}, status=status.HTTP_400_BAD_REQUEST)
                if user.is_verified == True:
                    return Response({'msg':'Your account is already verified...No verifictaion needed... You can login'},
                                     status= status.HTTP_405_METHOD_NOT_ALLOWED)
                if user.otp != otp:
                    return Response({'msg':'Wrong OTP'}, status= status.HTTP_400_BAD_REQUEST)
                if user.otp == otp:
                    ## make the user account verified and save the user data
                    user.is_verified = True      ## is_verified is a field in User model.. Bydefault it is false
                    user.save()
                    return Response({'msg':'Account verification is complete.... You can login'}, status= status.HTTP_200_OK)
            else:
                return Response({'msg':serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            # logger.error(str(e))
            return Response({'msg': str(e)}, status=status.HTTP_400_BAD_REQUEST)




        ## This is for User login
class UserLoginView(APIView):
    ## render the error message using custome render class
    renderer_classes = [UserRenderer]
    def post(self, request, format= None):
        try:
            serializer = UserLoginSerializer(data= request.data)
            if serializer.is_valid():        ## raise_exception= True
                email = serializer.data.get('email')
                password = serializer.data.get('password')
                    ## user the authenticate fuction to login the user and pass the user credentials
                user_auth = authenticate(email= email, password = password)
                    ## check the user_auth
                if user_auth is not None:
                    user = User.objects.get(email= email)
                        ## check the user account is verified or not
                    if user.is_verified == True:
                        if user.two_factor_enable:
                            auth_otp = serializer.validated_data.get("auth_otp", "Not define")
                            if auth_otp == "Not define":
                                return Response({'msg':'Your two factor authentication OTP is required... '}, status=status.HTTP_400_BAD_REQUEST)
                            refresh = CustomTokenObtainPairSerializer.get_token(user, auth_otp=auth_otp)
                            ## generate the token using serializer class
                        else:
                            refresh = CustomTokenObtainPairSerializer.get_token(user)
                            ## generate the refresh token
                        # refresh = RefreshToken.for_user(user)
                        token = {
                            'access':str(refresh.access_token),
                            'refresh':str(refresh)
                            }
                        # print(token)
                            ## generate the token using view class
                        # token_obtain_pair_view = CustomTokenObtainPairView()
                        # token_response = token_obtain_pair_view.post(request)
                        user.last_login = timezone.now()
                        user.save()
                        return Response({'token': token}, status=status.HTTP_200_OK)
                    else:
                        return Response({'msg':'User is not verified'}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({'msg':'Email or Password is not Valid'},status=status.HTTP_404_NOT_FOUND)
            else:
                return Response({'msg':serializer.errors}, status= status.HTTP_400_BAD_REQUEST)    
        except Exception as e:
            return Response({'msg': str(e)}, status=status.HTTP_400_BAD_REQUEST)



            ## this is for perticular user profile view
class UserProfileView(APIView):
    ## render the error message using custome render class
    renderer_classes = [UserRenderer]
        ## only authenticated user can see there profile details
    permission_classes = [IsAuthenticated]

    def get(self, request, format= None):
        try:
            user = request.user
            print(user)
            serializer = UserProfileSerializer(user, context={"user":user})
            return Response(serializer.data, status= status.HTTP_200_OK)
        except Exception as e:
            return Response({'msg': str(e)}, status=status.HTTP_400_BAD_REQUEST)




            ## this is for password change
class UserChangePasswordView(APIView):
    ## render the error message using custome render class
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format= None):
        try:
            serializer = UserChangePassword(data = request.data, context ={'user':request.user})
            if serializer.is_valid():

                #             ## If a user send some extra fields data.. Then this error will occure
                # input_data = set(serializer.initial_data.keys())
                # required_fields = set(serializer.fields.keys())
                # ext_data =  input_data - required_fields 
                # if ext_data:
                #     return Response({'msg':f"You have provided extra field {ext_data}"}, status.HTTP_400_BAD_REQUEST)
            
                return Response({'msg':'Password Changed Successfully'}, status.HTTP_200_OK)
            return Response({'msg':serializer.errors}, status= status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'msg': str(e)}, status=status.HTTP_400_BAD_REQUEST)




        ## this is for sending email to the user
class SendPasswordResetEmailView(APIView):
    ## render the error message using custome render class
    renderer_classes = [UserRenderer]
    def post(self, request, format= None):
        try:
            serializer = SendPasswordResetEmailSerializer(data = request.data)
            
            if serializer.is_valid():
            #     input_data = set(serializer.initial_data.keys())
            #     required_fields = set(serializer.fields.keys())
            #     ext_data =  input_data - required_fields 
            #     if ext_data:
            #         return Response({'msg':f"You have provided extra field {ext_data}"}, status.HTTP_400_BAD_REQUEST)
                
                return Response({'msg':'Password Reset OTP has been sent to your Email. Please check your Email'},
                                status= status.HTTP_200_OK)
            else:
                return Response({'msg':serializer.errors}, status= status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'msg': str(e)}, status=status.HTTP_400_BAD_REQUEST)





            ## this is for reset the password
class UserPasswordResetView(APIView):
    ## render the error message using custome render class
    renderer_classes = [UserRenderer]
    def post(self, request, format= None):
        try:
            serializer = UserPasswordResetSerializer(data= request.data)

            if serializer.is_valid():
                # input_data = set(serializer.initial_data.keys())
                # required_fields = set(serializer.fields.keys())
                # ext_data =  input_data - required_fields
                # if ext_data:
                #     return Response({'msg':f"You have provided extra field {ext_data}"}, status.HTTP_400_BAD_REQUEST)
                
                return Response({'msg':'Password reset successfull'}, status= status.HTTP_200_OK)
            else:
                return Response({'msg':serializer.errors}, status= status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'msg': str(e)}, status=status.HTTP_400_BAD_REQUEST)



class DeleteUserView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, fullName, format=None):
        try:
            user = self.request.user
            if user.is_superuser:
                    try:
                        user_data = User.objects.get(fullName=fullName)
                    except Exception as e:
                        return Response({'msg': f'User with {fullName} this name does not exist'}, status=status.HTTP_400_BAD_REQUEST)
                    user_data.delete()
                    return Response({'msg': 'User has been deleted successfully'}, status=status.HTTP_200_OK)
            else:
                return Response({'msg': 'You have no permission to delete a user'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'msg': str(e)}, status=status.HTTP_400_BAD_REQUEST)



    ## logout with serializer
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        try:
            serializer = CustomTokenBlacklistSerializer(data= request.data)
            if serializer.is_valid():
                # print(serializer.validated_data)
                # token = RefreshToken(serializer.validated_data['refresh'])
                # token.blacklist()
                return Response({'msg':"Logout successful"}, status= status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status= status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'msg':str(e)}, status= status.HTTP_400_BAD_REQUEST)



    ## logout without serializer
# class LogoutView(APIView):
#     permission_classes = [IsAuthenticated]

#     def post(self, request, format=None):
#         try:
#             if "refresh" in request.data:
#                 token = RefreshToken(request.data.get("refresh"))
#                 token.blacklist()
#                 return Response({'msg':"Logout successful"}, status= status.HTTP_200_OK)
#             else:
#                 return Response({'msg':"Refrest token required ..."}, status= status.HTTP_400_BAD_REQUEST)
#         except Exception as e:
#             return Response({'msg':str(e)}, status= status.HTTP_400_BAD_REQUEST)



class DeleteBlacklistAdOutstandingView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        try:
            user = request.user
            if user.is_superuser:
                outstanding , _ = OutstandingToken.objects.filter(expires_at__lte = timezone.now()).delete()
                    ## token  == > is the field name ......   created_at is the outstanding model field name which is a OneToOne field with token
                blacklist, _ = BlacklistedToken.objects.filter(token__created_at__lte= timezone.now()- timedelta(minutes=10)).delete()
                return Response({'msg':f'Deleted {outstanding} outstanding tokens and {blacklist} blacklisted tokens.'}, status= status.HTTP_200_OK)
                # return Response({'msg':"Deleted ....."}, status= status.HTTP_200_OK)
            return Response({'msg':"You have no permission...."}, status= status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'msg':str(e)}, status= status.HTTP_400_BAD_REQUEST)


## multiple user registration at a time
# class UserRegistrationByManagerView(APIView):
#     renderer_classes = [UserRenderer]
#     permission_classes = [IsAuthenticated]

#     def post(self, request, format=None):
#         try:
#             user = request.user
#             if user.team_leader and user.is_manager:
#                 serializer = UserRegistrationByManagerSerializer(data=list(request.data.values()), many=True, context={'request': request})
#                 if serializer.is_valid():
#                     valid_data = serializer.save()

#                     for data in valid_data:
#                         data.created_at = timezone.now()
#                         data.save()
#                         sent_otp_by_email(data.email)

#                     return Response({'msg': 'Registration Successful...Verify the user account'}, status.HTTP_201_CREATED)
#                 else:
#                     return Response({'msg': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
#             else:
#                 return Response({'msg': "You have no permission...."}, status=status.HTTP_400_BAD_REQUEST)
#         except Exception as e:
#             return Response({'msg': str(e)}, status=status.HTTP_400_BAD_REQUEST)






# class ActivationConfirm(APIView):
#     permission_classes = [AllowAny]
#     def get(self, request, uid, token):
#         try:
#             uid = force_str(urlsafe_base64_decode(uid))
#             user = User.objects.get(email=uid)
#             if default_token_generator.check_token(user, token):
#                 if user.is_verified:
#                     return render(request, 'account/welcome.html', {'user': user, 'msg':'Your account is verified..'})                
#                 user.is_verified = True
#                 user.save()
#                 return render(request, 'account/welcome.html', {'user': user , 'msg':'Your account verification is complete'})
#             else:
#                 return render(request, 'account/retry.html')
#         except Exception:
#             return render(request, 'account/retry.html')




# class ForgotPasswordEmailSendView(APIView):
#     renderer_classes = [UserRenderer]
#     def post(self, request, format= None):
#         try:
#             if "email" not in request.data:
#                 return Response({'msg':'Email is required'}, status= status.HTTP_400_BAD_REQUEST)
#             host_name = request.META.get('HTTP_HOST', None)
#             email = request.data.get('email')
#             if User.objects.filter(email = email).exists():
#                 user_acc = User.objects.get(email= email)
#                 uid = urlsafe_base64_encode(force_bytes(email))
#                 token = default_token_generator.make_token(user_acc)
#                 forgot_link = reverse('forgot_verify', kwargs={'uid': uid, 'token': token})
#                 forgot_verify = f'http://{host_name}{forgot_link}'
#                 send_forgot_pass_email(email, forgot_verify, host_name)
#                 user_acc.is_verified = False
#                 user_acc.save()
#                 return Response({'msg':'Password Reset link has been sent to your Email. Please check your Email'},
#                             status= status.HTTP_200_OK)
#             else:
#                 return Response({'msg':'You are not a user.....'}, status= status.HTTP_400_BAD_REQUEST)
#         except Exception as e:
#             return Response({'msg':str(e)}, status= status.HTTP_500_INTERNAL_SERVER_ERROR)



# class ForgotPasswordEmailVerifyView(APIView):
#     renderer_classes = [UserRenderer]
#     def get(self, request, uid, token , format= None):
#         try:
#             uid = force_str(urlsafe_base64_decode(uid))
#             user = User.objects.get(email=uid)
#             if default_token_generator.check_token(user, token):
#                 return render(request, 'account/reset_pass.html', {'user': user})
#             else:
#                 return render(request, 'account/retry.html', {'error':'Something went wrong.....'})
#         except Exception as e:
#         # except User.DoesNotExist:
#             return render(request, 'account/retry.html', {'error':'You are not a user..'})




# class ResetPasswordView(APIView):
#     def post(self, request, format=None):
#         try:
#             email = request.data.get('email')
#             password1 = request.data.get('password1')
#             password2 = request.data.get('password2')
#             user = User.objects.get(email= email)
#             if password1 != password2:
#                 return render(request, 'account/retry.html', {'error':'Password1 and Password does not match...'})
#             if len(password1) < 8:
#                 return render(request, 'account/retry.html', {'error':'Password must be 8 charecter long....'})
#             user.set_password(password1)
#             user.is_verified = True
#             user.save()
#             return render(request, 'account/welcome.html',{'msg':'Your password hase change successfully.......'} )
#         except Exception as e:
#             # print(str(e))
#             return render(request, 'account/retry.html', {'error':'Something went wrong.....'})









    


# class TOTPVerifyView(APIView):
#     """
#     Api to verify/enable a TOTP device
#     """
#     permission_classes = (IsAuthenticated, )
#     def post(self, request, token, format=None):
#         user = request.user
#         device = get_user_totp_device(self, user)
#         if not device:
#             return Response(dict(
#            errors=['This user has not setup two factor authentication']),
#                 status=status.HTTP_400_BAD_REQUEST
#             )
#         if not device == None and device.verify_token(token):
#             if not device.confirmed:
#                 device.confirmed = True
#                 device.save()
#                 user.is_two_factor_enabled=True
#                 user.save()
#             return Response(dict(token=user.token),   status=status.HTTP_200_OK)
#         return Response(dict(errors=dict(token=['Invalid TOTP Token'])),
#                         status=status.HTTP_400_BAD_REQUEST)