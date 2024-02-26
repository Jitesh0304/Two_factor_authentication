from rest_framework import serializers
from account.models import User
from account.utils import reset_pass_otp_email
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer , TokenBlacklistSerializer
from rest_framework_simplejwt.tokens import RefreshToken # AccessToken
import jwt
from decouple import config
from django.utils import timezone
from .validator import no_special_charecters
from account.utils import get_user_totp_device
from django.contrib.auth import authenticate


    ## custom token generator
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    auth_otp = serializers.IntegerField(required=False)

    def validate(self, attrs):
        self.user = authenticate(email= attrs.get("email", ''), password = attrs.get('password', ''))
        # data= super().validate(attrs)
        data = {}
        if 'auth_otp' in attrs:
            refresh = self.get_token(user=self.user, auth_otp= attrs.get("auth_otp"))
        else:
            refresh = self.get_token(user=self.user)
        data["refresh"] = str(refresh)
        data["access"] = str(refresh.access_token)
        return data


    @classmethod
        ## send the user data to get the token
    def get_token(cls, user, auth_otp=None):
            ## check the user is verify or not
        if user is not None and user.is_verified and user.two_factor_enable == False:
                ## generate token for the user.. it will give you refresh and access token
            token = super().get_token(user)
                # Add username and email to the token payload
                ## add extra field in the payload
            token['username'] = user.fullName
            token['email'] = user.email
            return token
        
        elif user is not None and user.is_verified and user.two_factor_enable == True:

            if not auth_otp:
                raise serializers.ValidationError("You have enable 2 factor auth ... Your auth OTP is required")

            device = get_user_totp_device(user)
            # print(auth_otp)
            if not device == None and device.verify_token(auth_otp):
                if not device.confirmed:
                    # print(" -- 1 -- ")
                    device.confirmed = True
                    device.save()
                    token = super().get_token(user)
                        # Add username and email to the token payload
                        ## add extra field in the payload
                    token['username'] = user.fullName
                    token['email'] = user.email
                    return token
                else:
                    # print(" -- 2 -- ")
                    token = super().get_token(user)
                    token['username'] = user.fullName
                    token['email'] = user.email
                    return token
            raise serializers.ValidationError("Not valid otp")
        else:
            raise serializers.ValidationError('You are not verified')
    # def validate(self, attrs):
    #     data = super().validate(attrs)
    #           # Add username and email to the response data
    #     data['fullName'] = self.user.fullName
    #     data['email'] = self.user.email
    #     return data


class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        ## call super() to get the access token and refresh token
        data = super().validate(attrs)
        ## validate the input data ( attrs )
        ## take the refresh token from the attrs
        refresh_token = RefreshToken(attrs['refresh'])
        ## take the user email from the refresh token
        email = refresh_token.payload.get('email')
        try:
            ## take the user details from the database
            user = User.objects.get(email = email)
            ## decode the generated jwt token
            decodeJTW = jwt.decode(str(data['access']), config('DJANGO_SECRET_KEY'), algorithms=["HS256"])
                # add payload here
            decodeJTW['username'] = str(user.fullName)
            decodeJTW['email'] = str(user.email)
            ## encode the modified jwt token
            encoded = jwt.encode(decodeJTW, config('DJANGO_SECRET_KEY'), algorithm="HS256")
            ## replace the access token with the modified one
            data['access'] = encoded
            data['two_factor_enable']= user.two_factor_enable
            user.last_login = timezone.now()
            user.save()
            ## return the newly generated token
            return data
        except:
            return data




        ## user registration 
class UserRegistrationSerializer(serializers.ModelSerializer):
        ## password field is write only
    password2 = serializers.CharField(required=True,style = {'input_type':'password'}, write_only =True)
    class Meta:
        model = User
        fields = ['email','fullName','password','password2','two_factor_enable']
        extra_kwargs = {
            'password':{'write_only':True},            ## password => write_only field
        }

            ## validate both passwords are same or not
    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        no_special_charecters(data.get('fullName'))
        if password != password2:
            raise serializers.ValidationError('Password and Confirm password does not match.....')
        if len(password) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long....")
        return data

                ## if the validation is successfull then create that user
    def create(self, validate_data):
        return User.objects.create_user(**validate_data)







            ## for OTP verification
class VerifyOtpSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()
    class Meta:
        fields = ['email','otp']



                ## This is for login page
class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length = 255)
    auth_otp = serializers.IntegerField(required=False)
    class Meta:
        model = User
        fields = ['email','password','auth_otp']               ## this two fields we need during login
    
    def validate_auth_otp(self, attrs):
        # print(attrs)
        return super().validate(attrs)




            ## this is for perticular user profile 
class UserProfileSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(format="%d/%m/%Y ")
    last_login = serializers.DateTimeField(format="%d/%m/%Y %H:%M:%S")
    class Meta:
        model = User
        fields = ['email','fullName','created_at','last_login','two_factor_enable']
    
    # def to_representation(self, instance):
    #     user = self.context.get('user')
    #     data = super().to_representation(instance)


            ## this is for password change
class UserChangePassword(serializers.Serializer):
    password = serializers.CharField(max_length= 255, style= {'input_type':'password'}, write_only =True)
    password2 = serializers.CharField(max_length= 255, style= {'input_type':'password'}, write_only =True)
    class Meta:
        fields = ['password','password2']

        ## validate both passwords are same or not
    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
            ## take the user data from context send from views class
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError('Password and Confirm password does not match')
        if len(password) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long....")
            ## set the new password in user account
        user.set_password(password)
        # print(user.check_password())
        user.save()
        return data




            ## this is for forgot password
class SendPasswordResetEmailSerializer(serializers.Serializer):
        ## for forgot password .. user email is required
    email = serializers.EmailField(max_length =255)
    class Meta:
        fileds = ['email']

        ## validate the email ... check any user present with this email or not
    def validate(self, data):
        email = data.get('email')
        if User.objects.filter(email= email, is_verified= True).exists():
            user = User.objects.get(email= email)
                ## call the custom forgot password function and sent the otp to the user account
            reset_pass_otp_email(user.email)
            return "Successful"
        else:
            raise serializers.ValidationError('You are not a Registered user or you have not verified your account...')



            ## this is for reset password
class UserPasswordResetSerializer(serializers.Serializer):
        ## for reset password these fields are required
    email = serializers.EmailField(max_length= 255)
    password = serializers.CharField(max_length= 255, style= {'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length= 255, style= {'input_type':'password'}, write_only=True)
    otp = serializers.CharField()
    class Meta:
        fields = ['email','password','password2','otp']

        ## validate the user details 
    def validate(self, data):
        try:
            email = data.get('email')
            password = data.get('password')
            password2 = data.get('password2')
            otp = data.get('otp')
            user = User.objects.get(email=email, is_verified=False)
            if password != password2:
                raise serializers.ValidationError('Password and Confirm password does not match')
            if len(password) < 8:
                raise serializers.ValidationError("Password must be at least 8 characters long....")
            if user.otp != otp:
                raise serializers.ValidationError('Wrong OTP')
            if user.otp == otp:
                ## if everything is verified make the user verified
                user.is_verified = True
                ## save the new password in user account
                user.set_password(password)
                user.save()
                return data
        except User.DoesNotExist:
            raise serializers.ValidationError('No user is present with this email.. Or your account is verified')
        except Exception as e:
            raise serializers.ValidationError(str(e))
            # raise serializers.ValidationError("Something went wrong")



class CustomTokenBlacklistSerializer(TokenBlacklistSerializer):
    def validate(self, attrs):
        refresh = attrs.get("refresh")
        token = RefreshToken(refresh).blacklist()
        return "success"