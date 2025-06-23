from rest_framework.permissions import BasePermission
from .models import GroupMemberModel


class IsGroupAdmin(BasePermission):

    def has_object_permission(self, request, view, obj):
        return obj.admin == request.user


class IsGroupPostViewer(BasePermission):

    def has_object_permission(self, request, view, obj):
        if obj.group.admin == request.user:
            return True

        return GroupMemberModel.objects.filter(
            group=obj.group, user=obj.user, is_banned=False
        ).exists()


class IsGroupPostOwner(BasePermission):

    def has_object_permission(self, request, view, obj):
        return obj.group.admin == request.user
