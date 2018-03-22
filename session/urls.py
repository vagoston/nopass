from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('session_login', views.session_login, name='session_login'),
    path('login', views.login_form, name='login_form'),
    path('register', views.register, name='register'),
    path('heartbeat', views.heartbeat, name='heartbeat'),
    path('out', views.out, name='out'),
    path('check', views.check, name='check'),
    path('get_qr', views.get_qr, name='get_qr_for_session'),
]