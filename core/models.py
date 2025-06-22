from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _
from .managers import UserManager


class User(AbstractUser):
    first_name = None
    last_name = None
    full_name = models.CharField(_("full name"), max_length=50)
    username = None
    email = models.EmailField(_("email address"), unique=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = UserManager()

    def get_short_name(self):
        return self.full_name

    def get_full_name(self):
        return self.full_name

    def __str__(self):
        return self.email


class GroupModel(models.Model):
    icon = models.ImageField(upload_to="images", blank=True, null=True)
    name = models.CharField(max_length=100, unique=True)
    description = models.CharField(max_length=400, blank=True, null=True)
    admin = models.ForeignKey(User, on_delete=models.CASCADE)
    whitelist = models.JSONField(default=list)
    blacklist = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class GroupMemberModel(models.Model):
    group = models.ForeignKey(GroupModel, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    is_banned = models.BooleanField(default=False)

    class Meta:
        unique_together = ("group", "user")

    def __str__(self):
        return self.user.email


class PostModel(models.Model):
    title = models.CharField(max_length=100)
    content = models.CharField(max_length=400)
    group = models.ForeignKey(GroupModel, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

