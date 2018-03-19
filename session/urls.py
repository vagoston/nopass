from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('session_login', views.session_login, name='session_login'),
    path('login', views.login_form, name='login_form'),
    path('register', views.register, name='register'),
    path('out', views.out, name='out'),
    path('check', views.check, name='check'),
]