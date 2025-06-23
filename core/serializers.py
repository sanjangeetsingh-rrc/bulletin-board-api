from rest_framework import serializers
from .models import User, GroupModel, PostModel, GroupMemberModel

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ["id", "full_name"]


class GroupSerializer(serializers.ModelSerializer):
    admin_name = serializers.CharField(source='admin.full_name')

    class Meta:
        model = GroupModel
        fields = ['id', 'name', 'description', 'icon', 'admin_name', 'created_at']


class GroupAdminSerializer(serializers.ModelSerializer):

    class Meta:
        model = GroupModel
        fields = ['id', 'name', 'description', 'icon', 'admin', 'whitelist', 'blacklist', 'created_at']
        read_only_fields = ['admin', 'created_at']


class PostSerializer(serializers.ModelSerializer):

    class Meta:
        model = PostModel
        fields = ['id', 'title', 'content', 'group', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']


class GroupMemberSerializer(serializers.ModelSerializer):
    user_email = serializers.EmailField(source='user.email', read_only=True)
    user_name = serializers.CharField(source='user.full_name', read_only=True)

    class Meta:
        model = GroupMemberModel
        fields = ['id', 'user_email', 'user_name', 'is_banned']
        read_only_fields = ['user_email', 'user_name']

