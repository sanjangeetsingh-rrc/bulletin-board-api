from django.urls import path
from .views import (
    login,
    login_renew,
    signup,
    signup_verify,
    reset_password,
)

urlpatterns = [
    path('login/', login, name='login'),
    path('login/renew/', login_renew, name='login_renew'),
    path('signup/', signup, name='signup'),
    path('signup/request-otp/', signup_verify, name='signup_verify'),
    path('reset-password/', reset_password, name='reset_password'),
]
