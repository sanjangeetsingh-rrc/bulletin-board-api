from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import permission_classes
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from django.contrib.auth import authenticate
from django.core.validators import validate_email
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
import pyotp
from .models import User
from .utils import redis_client


@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response({'error': list(filter(lambda x: x is not None, [
            'Email is required' if not email else None,
            'Password is required' if not password else None,
        ]))}, status=status.HTTP_400_BAD_REQUEST)

    email = email.strip().lower()
    password = password.strip()

    try:
        validate_email(email)
    except ValidationError:
        return Response({'error': 'Invalid email'}, status=status.HTTP_400_BAD_REQUEST)

    user = authenticate(request, email=email, password=password)

    if not user:
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

    refresh = RefreshToken.for_user(user)
    return Response({
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
def login_renew(request):
    refresh = request.data.get('refresh')

    if not refresh:
        return Response({'error': 'Refresh token is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        refresh = RefreshToken(refresh)
    except:
        return Response({'error': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)

    return Response({'token': str(refresh.access_token)}, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
def signup(request):
    email = request.data.get('email')
    otp = request.data.get('otp')
    password = request.data.get('password')

    if not email or not otp or not password:
        return Response({'error': list(filter(lambda x: x is not None, [
            'Email is required' if not email else None,
            'OTP is required' if not otp else None,
            'Password is required' if not password else None,
        ]))}, status=status.HTTP_400_BAD_REQUEST)

    email = email.strip().lower()
    password = password.strip()
    otp = otp.strip()

    try:
        validate_email(email)
    except ValidationError:
        return Response({'error': 'Invalid email'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email=email).exists():
        return Response({'error': 'User already exists'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        validate_password(password)
    except ValidationError as e:
        return Response({'error': e.messages}, status=status.HTTP_400_BAD_REQUEST)

    redis_key = f'auth:signup:{email}'
    if not redis_client.exists(redis_key) or otp != redis_client.get(redis_key):
        return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.create_user(email=email, password=password)
    redis_client.delete(redis_key)

    refresh = RefreshToken.for_user(user)
    return Response({
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
def signup_verify(request):
    email = request.data.get('email')

    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

    email = email.strip().lower()

    try:
        validate_email(email)
    except ValidationError:
        return Response({'error': 'Invalid email'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email=email).exists():
        return Response({'error': 'User already exists'}, status=status.HTTP_400_BAD_REQUEST)

    otp = pyotp.TOTP(pyotp.random_base32()).now()
    redis_client.setex(f'auth:signup:{email}', 900, otp)

    try:
        send_mail(
            subject=f'OTP - {otp}',
            message=f'Your OTP code is {otp}. This code will expire in 15 minutes. If you did not request this, please ignore this email.',
            recipient_list=[email],
        )
    except:
        redis_client.delete(f'auth:signup:{email}')
        return Response({}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response({}, status=status.HTTP_200_OK)

