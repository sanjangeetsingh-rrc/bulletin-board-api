from rest_framework.decorators import api_view
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework import filters
from rest_framework.decorators import action
from rest_framework import status
from rest_framework.decorators import permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.parsers import MultiPartParser, FormParser
from django.core.mail import send_mail
from django.contrib.auth import authenticate
from django.core.validators import validate_email
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.conf import settings
import pyotp
from .permissions import IsGroupAdmin, IsGroupPostOwner, IsGroupPostViewer
from .models import User, GroupModel, GroupMemberModel, PostModel
from .serializers import UserSerializer, GroupSerializer, GroupAdminSerializer, PostSerializer, GroupMemberSerializer
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

    return Response({'access': str(refresh.access_token)}, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
def signup(request):
    full_name = request.data.get('full_name')
    email = request.data.get('email')
    otp = request.data.get('otp')
    password = request.data.get('password')

    if not email or not otp or not password or not full_name:
        return Response({'error': list(filter(lambda x: x is not None, [
            'Email is required' if not email else None,
            'OTP is required' if not otp else None,
            'Password is required' if not password else None,
            'Full name is required' if not full_name else None,
        ]))}, status=status.HTTP_400_BAD_REQUEST)

    email = email.strip().lower()
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

    user = User.objects.create_user(full_name=full_name, email=email, password=password)
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

    redis_key = f'auth:signup:{email}'
    if redis_client.exists(redis_key):
        if redis_client.ttl(redis_key) > 780:
            return Response({'error': 'Please wait for 2 minutes before requesting another OTP'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

    otp = pyotp.TOTP(pyotp.random_base32()).now()
    redis_client.setex(f'auth:signup:{email}', 900, otp)

    try:
        send_mail(
            subject=f'OTP - {otp}',
            message=f'Your OTP code is {otp}. This code will expire in 15 minutes. If you did not request this, please ignore this email.',
            recipient_list=[email],
            from_email=settings.DEFAULT_FROM_EMAIL,
        )
    except:
        redis_client.delete(f'auth:signup:{email}')
        return Response({}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response({}, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password(request):
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
    otp = otp.strip()

    user = User.objects.filter(email=email).first()

    if not user:
        return Response({'error': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        validate_password(password)
    except ValidationError as e:
        return Response({'error': e.messages}, status=status.HTTP_400_BAD_REQUEST)

    redis_key = f'auth:signup:{email}'
    if not redis_client.exists(redis_key) or otp != redis_client.get(redis_key):
        return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

    user.set_password(password)
    user.save()
    redis_client.delete(redis_key)

    return Response({}, status=status.HTTP_200_OK)


@api_view(['GET'])
def user_info(request):
    serializer = UserSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['POST'])
def user_update(request):
    serializer = UserSerializer(request.user, data=request.data, partial=True)

    if serializer.is_valid():
        serializer.save()
        return Response({}, status=status.HTTP_200_OK)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def change_password(request):
    old_password = request.data.get("old_password")
    new_password = request.data.get("new_password")

    if not old_password or not new_password:
        return Response({'error': list(filter(lambda x: x is not None, [
            'Old password is required' if not old_password else None,
            'New password is required' if not new_password else None,
        ]))}, status=status.HTTP_400_BAD_REQUEST)

    user = request.user
    if not user.check_password(old_password):
        return Response({'error': 'Incorrect password'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        validate_password(new_password)
    except ValidationError as e:
        return Response({'error': e.messages}, status=status.HTTP_400_BAD_REQUEST)

    user.set_password(new_password)
    user.save()

    return Response({}, status=status.HTTP_200_OK)


class GroupViewSet(viewsets.ModelViewSet):
    queryset = GroupModel.objects.all()
    filter_backends = [filters.SearchFilter]
    search_fields = ['name']
    parser_classes = [MultiPartParser, FormParser]

    def get_permissions(self):
        if self.action in ['update', 'partial_update', 'destroy']:
            permission_classes = [IsAuthenticated, IsGroupAdmin]
        else:
            permission_classes = [IsAuthenticated]

        return [permission() for permission in permission_classes]

    def get_serializer_class(self):
        if self.action in ['update', 'partial_update', 'create']:
            return GroupAdminSerializer
        else:
            return GroupSerializer

    def perform_create(self, serializer):
        serializer.save(admin=self.request.user)

    @action(methods=['get'], detail=False)
    def my(self, request):
        groups = GroupModel.objects.filter(admin=request.user)
        serializer = self.get_serializer(groups, many=True)
        return Response(serializer.data)

    @action(methods=['get'], detail=False)
    def joined(self, request):
        member_group_ids = GroupMemberModel.objects.filter(
            user=request.user
        ).exclude(group__admin=request.user).values_list('group_id', flat=True)

        groups = GroupModel.objects.filter(id__in=member_group_ids)

        serializer = GroupSerializer(groups, many=True)
        return Response(serializer.data)

    @action(methods=['get'], detail=False)
    def list_members(self, request):
        group = request.query_params.get('group')

        if not group:
            return Response({'detail': 'Group ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            group = GroupModel.objects.get(id=group)
        except GroupModel.DoesNotExist:
            return Response({'detail': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)

        if group.admin != request.user:
            return Response({'detail': 'You are not the admin of this group.'}, status=status.HTTP_403_FORBIDDEN)

        members = GroupMemberModel.objects.filter(group=group).select_related('user')
        serializer = UserSerializer([m.user for m in members], many=True)
        return Response(serializer.data)

    @action(methods=['post'], detail=False)
    def ban_member(self, request):
        group = request.data.get('group')
        user = request.data.get('user')

        if not group or not user:
            return Response({'detail': 'Both group and user are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            group = GroupModel.objects.get(id=group)
        except GroupModel.DoesNotExist:
            return Response({'detail': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)

        if group.admin != request.user:
            return Response({'detail': 'You are not the admin of this group.'}, status=status.HTTP_403_FORBIDDEN)

        try:
            member = GroupMemberModel.objects.get(group=group, user_id=user)
        except GroupMemberModel.DoesNotExist:
            return Response({'detail': 'User is not a member of this group.'}, status=status.HTTP_404_NOT_FOUND)

        member.is_banned = True
        member.save()
        return Response({'detail': f'User {member.user.email} has been banned.'}, status=status.HTTP_200_OK)


class PostViewSet(viewsets.ModelViewSet):
    queryset = PostModel.objects.all().order_by('-created_at')
    serializer_class = PostSerializer

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            permission_classes = [IsAuthenticated, IsGroupPostOwner]
        elif self.action in ['retrieve', 'list']:
            permission_classes = [IsAuthenticated, IsGroupPostViewer]
        return [permission() for permission in permission_classes]

    @action(methods=['get'], detail=False)
    def group_posts(self, request):
        user = request.user
        group = request.query_params.get('group')

        if not group:
            return Response({'detail': 'Group ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            group_id = int(group)
        except ValueError:
            return Response({'detail': 'Invalid group id'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            group = GroupModel.objects.get(id=group_id)
        except GroupModel.DoesNotExist:
            return Response({'detail': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)

        is_admin = group.admin == user
        is_member = GroupMemberModel.objects.filter(group=group, user=user, is_banned=False).exists()

        if not (is_admin or is_member):
            return Response({'detail': 'Not authorized to view posts of this group.'}, status=status.HTTP_403_FORBIDDEN)

        posts = PostModel.objects.filter(group=group).order_by('-created_at')
        serializer = self.get_serializer(posts, many=True)
        return Response(serializer.data)


@api_view(['POST'])
def join_group(request):
    user = request.user
    user_email = request.user.email
    domain = user_email.split('@')[1]
    group = request.data.get('group')

    if not group:
        return Response({'detail': 'Group ID is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        group = GroupModel.objects.get(id=group)
    except GroupModel.DoesNotExist:
        return Response({'detail': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)

    if group.admin == user:
        return Response({'detail': 'Group admin is already considered a member.'}, status=status.HTTP_400_BAD_REQUEST)

    if user_email in group.blacklist or domain in group.blacklist:
        return Response({'detail': 'You are blacklisted from this group.'}, status=status.HTTP_403_FORBIDDEN)

    if group.whitelist != [] and not (user_email in group.whitelist or domain in group.whitelist):
        return Response({'detail': 'You are not whitelisted for this group.'}, status=status.HTTP_403_FORBIDDEN)

    existing = GroupMemberModel.objects.filter(group=group, user=user).first()
    if existing:
        if existing.is_banned:
            return Response({'detail': 'You are banned from this group.'}, status=status.HTTP_403_FORBIDDEN)
        return Response({'detail': 'You are already a member.'}, status=status.HTTP_200_OK)

    GroupMemberModel.objects.create(group=group, user=user)
    return Response({}, status=status.HTTP_200_OK)


@api_view(['POST'])
def leave_group(request):
    user = request.user
    group = request.data.get('group')

    if not group:
        return Response({'detail': 'Group ID is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        group = GroupModel.objects.get(id=group)
    except GroupModel.DoesNotExist:
        return Response({'detail': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)

    if group.admin == user:
        return Response({'detail': 'Group admin cannot leave their own group.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        member = GroupMemberModel.objects.get(group=group, user=user)
    except GroupMemberModel.DoesNotExist:
        return Response({'detail': 'You are not a member of this group.'}, status=status.HTTP_400_BAD_REQUEST)

    if member.is_banned:
        return Response({'detail': 'Banned members cannot leave the group.'}, status=status.HTTP_403_FORBIDDEN)

    member.delete()
    return Response({}, status=status.HTTP_200_OK)

