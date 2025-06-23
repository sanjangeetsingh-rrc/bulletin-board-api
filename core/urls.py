from rest_framework.routers import DefaultRouter
from django.urls import path
from .views import (
    login,
    login_renew,
    signup,
    signup_verify,
    reset_password,
    user_info,
    user_update,
    change_password,
    GroupViewSet,
    PostViewSet,
)

router = DefaultRouter()
router.register(r'groups', GroupViewSet, basename='group')
router.register(r'posts', PostViewSet, basename='post')

urlpatterns = [
    path('login/', login, name='login'),
    path('login/renew/', login_renew, name='login_renew'),
    path('signup/', signup, name='signup'),
    path('signup/request-otp/', signup_verify, name='signup_verify'),
    path('reset-password/', reset_password, name='reset_password'),
    path('user/info/', user_info, name='user_info'),
    path('user/update/', user_update, name='user_update'),
    path('user/change-password/', change_password, name='change_password'),
]

urlpatterns += router.urls
