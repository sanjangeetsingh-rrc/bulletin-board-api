from rest_framework import serializers
from .models import User, GroupModel, PostModel

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ["full_name"]


class GroupSerializer(serializers.ModelSerializer):

    class Meta:
        model = GroupModel
        fields = ["icon", "name", "description", "admin", "created_at"]


class PostSerializer(serializers.ModelSerializer):

    class Meta:
        model = PostModel
        fields = "__all__"
