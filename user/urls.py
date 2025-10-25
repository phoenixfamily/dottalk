from django.urls import path
from . import views
from .views import dashboard_view

app_name = "user"

urlpatterns = [
    path("api/register/options/", views.webauthn_register_options, name='register-option'),
    path("api/register/verify/", views.webauthn_register_verify, name='register-verify'),
    path("api/login/options/", views.webauthn_login_options, name='login-option'),
    path("api/login/verify/", views.webauthn_login_verify, name='login-verify'),

    path('dashboard/', dashboard_view, name='dashboard'),

]
