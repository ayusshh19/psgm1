from random import choice
from django.contrib.auth.hashers import make_password, check_password
from django.core.mail import send_mail
from django.http.response import JsonResponse, HttpResponse
from django.template import loader
from rest_framework import status
from datetime import datetime, timedelta, timezone
import json
from rest_framework.decorators import api_view
from django.views.decorators.csrf import csrf_exempt
import requests
from uuid import uuid4
from urllib3.exceptions import InsecureRequestWarning
from django.utils.html import escape
from .serializers import UserSerializer, delserializer, homeserializer, passwordserializer
from .models import LoginLogs, PasswordHistory, PasswordResetLogs, Passwords, Tokens, delete_account, reg, home
import urllib.request as ur
from django.utils import timezone
HEADERS = {"x-api-token": "Industry4132Pass"}
BASE_URL = "https://iiot.solargroup.com:6070/apiph/"
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
def home_view(request,id):
    if request.method=='POST':
        if reg.objects.filter(id=id).exists:
            user_type=reg.objects.get(id=id)
            print(user_type.user_type)
            if user_type.user_type=='owner':
                data=request.data
                homie=homeserializer(data=data)
                if homie.is_valid():
                    homie.save()
                    return JsonResponse({"message":"thanks"})
                else:
                    new_data=home.objects.all()
                    return JsonResponse(new_data)
        else:
            return JsonResponse({"message":"id does not exist"}) 
    else:
        return JsonResponse({"message":"method error"})
@api_view(['POST', 'PUT','GET'])
def login(request):  
    if request.method == 'PUT' or request.method == 'POST' or request.method == 'GET':
        Username=request.data.get('Username')
        pass1=request.data.get('pass1')
    
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        url = 'https://ipapi.co/' + ip + '/json/'
        contents = ur.urlopen(url).read()
        try:
            contents = json.loads(contents)
            loginlog = LoginLogs.objects.create(
                log_date=timezone.now(),
                request_page='Login',
                time_zone=contents['utc_offset'],
            )
        except KeyError:
            loginlog = LoginLogs.objects.create(
                log_date=timezone.now(),
                request_page='Login',
                isactive=2
            )
        try:
            userobj = reg.objects.get(Username=Username)
            passwordobj = Passwords.objects.get(user=userobj.id)

            loginlog.user = userobj
            ind_serializer = UserSerializer(userobj)

            if check_password(pass1,passwordobj.value):

                if passwordobj.unlocks_on:
                    if passwordobj.unlocks_on > timezone.now():
                        remaining_time = (passwordobj.unlocks_on - timezone.now()).seconds
                        message = 'Try again later in ' + str(remaining_time // 60) + ' minutes ' + str(
                            remaining_time % 60) + ' seconds.'
                        loginlog.login_status = False
                        loginlog.cause = 'Acccount Temporarily Locked Out'
                        loginlog.save()
                        return JsonResponse(
                            {'message': message, 'success': False, 'login_id': userobj.user_id, 'auth_token': '',
                             'auth_id': ''}, status=status.HTTP_429_TOO_MANY_REQUESTS)

                try:
                    Tokens.objects.filter(user=userobj).delete()
                except Tokens.DoesNotExist:
                    pass

                token_code = str(uuid4())
                Tokens.objects.create(value=token_code, valid_upto=timezone.now() + timedelta(minutes=40), user=userobj)

                passwordobj.failed_attempts = 0
                passwordobj.failed_attempt_time = None
                passwordobj.unlocks_on = None
                Lastlogin = passwordobj.last_login_on
                passwordobj.last_login_on = timezone.now()
                passwordobj.save()
                message = 'Welcome! ' + str(userobj.first_name)
                ChangeRequired = passwordobj.isdefault or (
                            (passwordobj.last_reset_date + timedelta(days=60)) <= datetime.today().date())
                loginlog.login_status = True
                loginlog.save()
                o = ind_serializer.data
                o['auth_token'] = token_code
                o['message'] = message
                o['success'] = Lastlogin
                o['message'] = True
                o['change_required'] = ChangeRequired
                # LOGIN ACCEPTED RESPONSE SEND ALL OTHER NECESSARY INFORMATION ALONG WITH THIS
                return JsonResponse(o, status=status.HTTP_202_ACCEPTED, safe=False)
            else:
                passwordobj.failed_attempts += 1
                passwordobj.failed_attempt_time = timezone.now()

                if passwordobj.failed_attempts >= 5:
                    if passwordobj.unlocks_on == None:
                        passwordobj.unlocks_on = timezone.now() + timedelta(minutes=20)
                        loginlog.cause = 'Incorrect Password Entered, attempt: 5 Account Locked!'
                        message = 'Too many unsuccessful attempts, Your Account has been Temporarily Blocked. Try again in 20 minutes.'

                    elif passwordobj.unlocks_on < timezone.now():
                        passwordobj.failed_attempts = 1
                        passwordobj.failed_attempt_time = timezone.now()
                        passwordobj.unlocks_on = None
                        loginlog.cause = 'Incorrect Password Entered, attempt: ' + str(passwordobj.failed_attempts)
                        message = 'Invalid Credentials. Please check Username or Password. Unsuccessful attempts: ' + str(
                            passwordobj.failed_attempts) + ', After ' + str(
                            5 - passwordobj.failed_attempts) + ' more attempts, account will be temporarily blocked.'

                    else:
                        remaining_time = (passwordobj.unlocks_on - timezone.now()).seconds
                        loginlog.cause = 'Acccount Temporarily Locked Out'
                        message = 'Try again later in ' + str(remaining_time // 60) + ' minutes ' + str(
                            remaining_time % 60) + ' seconds.'

                    passwordobj.save()
                    loginlog.login_status = False
                    loginlog.save()
                    return JsonResponse({
                        'message': message,
                        'success': False,
                        'loginId': 0,
                        'auth_token': '',
                        'auth_id': ''
                    }, status=status.HTTP_429_TOO_MANY_REQUESTS)

                else:
                    loginlog.cause = 'Incorrect Password Entered, attempt: ' + str(passwordobj.failed_attempts)
                    loginlog.login_status = False
                    loginlog.save()
                    message = 'Invalid Credentials. Please check Username or Password. Unsuccessful attempts: ' + str(
                        passwordobj.failed_attempts) + ', After ' + str(
                        5 - passwordobj.failed_attempts) + ' more attempts, account will be temporarily blocked.'
                    passwordobj.save()
                    return JsonResponse({'message': message, 'success': False, 'login_id': 0}, status=status.HTTP_200_OK)

        except reg.DoesNotExist:
            loginlog.cause = 'Invalid Login'
            loginlog.login_status = False
            loginlog.save()
            return JsonResponse({"Message": "no login "}, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
@api_view(['POST', 'PUT'])
def signup1(request):
    if request.method == 'PUT' or request.method == 'POST':
        data = request.data
        if not data['Username'] or not data['Fname'] or not data['Lname'] or not data['phone_number'] or not data['pass1'] or not data['Email'] or not data['pan_no'] or not data['Address'] :
            return JsonResponse({"Message": "Coudln't get data from site"}, status=status.HTTP_204_NO_CONTENT)
        else:
            existing_email =reg.objects.filter(Email=data['Email'])
            if not existing_email:
                password = {}
                password['value'] = make_password(data['pass1'], salt=None, hasher='default') 
                password['failed_attempt_time'] = None
                password['last_login_on'] = None
                password['last_reset_on'] = None
                password['last_reset_date'] = None
                password['last_reset_time'] = None
                password['unlocks_on'] = None
                password['isdefault'] = True
                password['failed_attempt_time'] = None
                general_serialized = UserSerializer(data=data)
                if general_serialized.is_valid():
                    general_serialized.save()
                    # return JsonResponse(obj)  
                else:
                    return HttpResponse(general_serialized.errors)
                password_serialized = passwordserializer(data=password)
                if password_serialized.is_valid():
                    password_serialized.save()
            else:
                return JsonResponse({"Message": "Email Already Exists"}, status=status.HTTP_406_NOT_ACCEPTABLE)
        return JsonResponse({"Message": "Account Created Successfully"}, status=status.HTTP_201_CREATED)
    else:
        # Wrong Request method
        return JsonResponse({"Message": "Wrong Request Method"}, status=status.HTTP_400_BAD_REQUEST)
# Create your views here.

# TOKEN CHECKER
def TokenChecker(Wrapped):
    def wrapper(*args, **kwargs):
        request = args[0]

        try:
            tokenval = request.META['HTTP_AUTHORIZATION'].split(' ')[1]
            userid = request.META['HTTP_AUTHORIZATION'].split(' ')[2]
        except (KeyError, IndexError):
            return HttpResponse('<h1>Unauthorized(401)</h1>', status=status.HTTP_401_UNAUTHORIZED)

        try:
            user = reg.objects.get(id=userid)
        except reg.DoesNotExist:
            return HttpResponse('<h1>Unauthorized(401)</h1>', status=status.HTTP_401_UNAUTHORIZED)

        try:
            token = Tokens.objects.get(user=user)
        except Tokens.DoesNotExist:
            return HttpResponse('<h1>Unauthorized(401)</h1>', status=status.HTTP_401_UNAUTHORIZED)

        # VALID LOGIN
        if token.value == tokenval and token.valid_upto > timezone.now():
            return Wrapped(*args, **kwargs)

        else:
            return HttpResponse('<h1>Token Expired(401)</h1>', status=status.HTTP_401_UNAUTHORIZED)

    return wrapper


@api_view(['POST'])
def PasswordChanger(request):
    newpassword = request.data.get('password')

    if request.GET.get('type') == 'forgot':
        email = request.data.get('email')
        if newpassword:
            userobj = reg.objects.get(email=email)
            paswordobj = Passwords.objects.get(user=userobj)
            otp = request.data.get('otp')
            try:
                otpobj = PasswordResetLogs.objects.get(user=userobj, isactive=1)

                if otpobj.forgot_token != str(otp):
                    if otpobj.attempts >= 3:
                        return JsonResponse(
                            {'message': 'Too Many Incorrect OTPs entered, Please request a new one', 'success': False},
                            status=status.HTTP_429_TOO_MANY_REQUESTS)
                    else:
                        otpobj.attempts += 1
                        otpobj.save()
                        return JsonResponse({'message': 'Wrong OTP Entered, Try Again!', 'success': False})

                if otpobj.expires_on > timezone.now():
                    if paswordobj.value == newpassword:
                        return JsonResponse(
                            {'message': 'New Password cannot be the same as old password', 'success': False})
                    else:
                        paswordobj.value = escape(newpassword)
                        paswordobj.last_reset_on = timezone.now()
                        paswordobj.last_reset_date = datetime.today().date()
                        paswordobj.last_reset_time = timezone.now().time()
                        paswordobj.passwords_changed += 1
                        paswordobj.isdefault = False

                        PasswordHistory.objects.create(
                            user=userobj,
                            changed_on=timezone.now(),
                            new_password=escape(newpassword),
                            old_password=paswordobj.value
                        )

                        paswordobj.save()
                        otpobj.isactive = 0
                        otpobj.save()
                        return JsonResponse({'message': 'Password Changed Successfully', 'success': True},
                                            status=status.HTTP_202_ACCEPTED)
                else:
                    return JsonResponse({'message': 'OTP Expired', 'success': False})

            except PasswordResetLogs.DoesNotExist:
                return JsonResponse(
                    {'message': 'Invalid Request, No Active OTP associated to user. Please Request a New one',
                     'success': False})

        else:
            return JsonResponse({'message': 'Invalid Request', 'success': False}, status=status.HTTP_400_BAD_REQUEST)

    if request.GET.get('type') == 'login':
        # id = request.data.get('id')
        email = request.data.get('email')

        if TokenChecker(request, email) == True:
            if newpassword:
                userobj = reg.objects.get(email=email)
                paswordobj = Passwords.objects.get(password=userobj)
                if paswordobj.value == newpassword:
                    return JsonResponse(
                        {'message': 'New Password cannot be the same as old password', 'success': False})
                else:
                    paswordobj.value = escape(newpassword)
                    paswordobj.last_reset_on = timezone.now()
                    paswordobj.last_reset_date = datetime.today().date()
                    paswordobj.last_reset_time = timezone.now().time()
                    paswordobj.passwords_changed += 1
                    paswordobj.isdefault = False

                    PasswordHistory.objects.create(
                        user=userobj,
                        changed_on=timezone.now(),
                        new_password=escape(newpassword),
                        old_password=paswordobj.value
                    )

                    paswordobj.save()
                    return JsonResponse({'message': 'Password Changed Successfully', 'success': True},
                                        status=status.HTTP_202_ACCEPTED)
            else:
                return JsonResponse({'message': 'Invalid Request', 'success': False},
                                    status=status.HTTP_400_BAD_REQUEST)

        else:
            return TokenChecker(request, id)

@api_view(['POST'])
def ForgotPassword(request):
    email = request.data.get('email')

    try:
        userobj = reg.objects.get(email=email)
        otp = ''.join(choice('0123456789') for i in range(6))
        email = userobj.email

        if PasswordResetLogs.objects.filter(user=userobj, request_date=datetime.today().date()).count() >= 5:
            return JsonResponse(
                {'message': "You've Exceeded Maximum OTP requests for today. Try Again Tomorrow", 'success': False},
                status=status.HTTP_429_TOO_MANY_REQUESTS)
        else:
            PasswordResetLogs.objects.filter(user=userobj).update(isactive=0)
            PasswordResetLogs.objects.create(
                user=userobj,
                isactive=1,
                request_date=datetime.today().date(),
                expires_on=timezone.now() + timedelta(minutes=10),
                forgot_token=otp
            )

            html_message = loader.render_to_string(
                'ForgotPassword.html',
                {
                    'username': userobj.email,
                    'name': userobj.first_name,
                    'OTP': otp,
                }
            )

            send_mail('psgm: Password Recovery Request. Do-not-reply',
                      'Text Alternative',
                      'js1910492@gmail.com',
                      [email],
                      html_message=html_message
                      )

            return JsonResponse({'message': 'OTP Sent to your Associated Email.', 'success': True})

    except reg.DoesNotExist:
        return JsonResponse({'message': 'Username Incorrect. Please enter your proper username', 'success': False})

@api_view(['POST'])
def del_ac(request, userid):
    if request.method == 'POST':
        fet = reg.objects.get(id=userid)
        try:
            del_serial=delserializer(data=fet)
            if del_serial.is_valid():
                del_serial.save()
                reg.objects.filter(id=userid).update(status=False, updated_at=timezone.now())
                return HttpResponse('Account Deleted Successfully')

        except Tokens.DoesNotExist:
            return HttpResponse('Account Deletion Failed')
    else:
        return JsonResponse({"status": False, "Desc": "Wrong Request Method"})