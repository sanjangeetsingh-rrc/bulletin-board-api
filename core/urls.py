from django.urls import path
from .views import (
    login,
    login_renew,
    signup,
    signup_verify,
)

urlpatterns = [
    path('login/', login, name='login'),
    path('login/renew/', login_renew, name='login_renew'),
    path('signup/', signup, name='signup'),
    path('signup/verify/', signup_verify, name='signup_verify'),
]
