from django.urls import path
from .views import (
    login,
    signup,
    signup_verify,
)

urlpatterns = [
    path('login/', login, name='login'),
    path('signup/', signup, name='signup'),
    path('signup/verify/', signup_verify, name='signup_verify'),
]
