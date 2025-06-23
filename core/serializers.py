from rest_framework import serializers
from .models import User, GroupModel, PostModel

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ["full_name"]


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

