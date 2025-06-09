from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.validators import validate_email
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.conf import settings
from django.core.mail import send_mail
from django.contrib.auth import authenticate
import pyotp
from .utils import redis_client
from .models import User

@api_view(['POST'])
def login(request):
    email = request.data.get('email')
    password = request.data.get('password')

    errors = []
    if not email:
        errors.append('The email is required')
    if not password:
        errors.append('The password is required')
    if errors:
        return Response({
            'error': errors
        }, status=status.HTTP_400_BAD_REQUEST)

    try:
        validate_email(email)
    except ValidationError:
        return Response({
            'error': ['Invalid email format']
        }, status=status.HTTP_400_BAD_REQUEST)

    user = authenticate(request, email=email, password=password)

    if not user:
        return Response({
            'error': ['Invalid credentials']
        }, status=status.HTTP_400_BAD_REQUEST)

    refresh = RefreshToken.for_user(user)
    return Response({
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }, status=status.HTTP_200_OK)

@api_view(['POST'])
def signup(request):
    email = request.data.get('email')
    otp = request.data.get('otp')
    password = request.data.get('password')

    errors = []
    if not email:
        errors.append('The email is required')
    if not password:
        errors.append('The password is required')
    if not otp:
        errors.append('The otp is required')
    if errors:
        return Response({
            'error': errors
        }, status=status.HTTP_400_BAD_REQUEST)

    try:
        validate_email(email)
    except ValidationError:
        return Response({
            'error': ['Invalid email format']
        }, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email=email).exists():
        return Response({
            'error': ['User already exists']
        }, status=status.HTTP_400_BAD_REQUEST)

    try:
        validate_password(password)
    except ValidationError as e:
        return Response({
            'error': e.messages
        }, status=status.HTTP_400_BAD_REQUEST)

    redis_key = f'signup:{email}'

    if not redis_client.exists(redis_key) or otp != redis_client.get(redis_key):
        return Response({
            'error': ['Invalid otp']
        }, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.create_user(email=email, password=password)
    redis_client.delete(redis_key)

    refresh = RefreshToken.for_user(user)
    return Response({
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }, status=status.HTTP_200_OK)

@api_view(['POST'])
def signup_verify(request):
    email = request.data.get('email')

    if not email:
        return Response({
            'error': ['The email is required']
        }, status=status.HTTP_400_BAD_REQUEST)

    try:
        validate_email(email)
    except ValidationError:
        return Response({
            'error': ['Invalid email format']
        }, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email=email).exists():
        return Response({
            'error': ['User already exists']
        }, status=status.HTTP_400_BAD_REQUEST)

    otp = pyotp.TOTP(pyotp.random_base32()).now()
    redis_client.setex(f'signup:{email}', 900, otp)

    try:
        send_mail(
            subject='Verify your email',
            message=f'Your verification code is {otp}. This code will expire in 15 minutes.',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
        )
    except:
        redis_client.delete(f'signup:{email}')
        return Response({}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response({}, status=status.HTTP_200_OK)
