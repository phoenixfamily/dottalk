from django.urls import path
from .views import *

app_name = "user"

urlpatterns = [
    path("api/register/options/", webauthn_register_options, name='register-option'),
    path("api/register/verify/", webauthn_register_verify, name='register-verify'),
    path("api/login/options/", webauthn_login_options, name='login-option'),
    path("api/login/verify/", webauthn_login_verify, name='login-verify'),

    path('login/', login_view, name='login-view'),
    path('register/', register_view, name='register-view'),

    path('captcha/', custom_captcha, name='custom-captcha'),

    path('dashboard/', dashboard_view, name='dashboard-view'),

]
