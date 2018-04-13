from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'session_login', views.session_login, name='session_login'),
    url(r'login', views.login_form, name='login_form'),
    url(r'register', views.register, name='register'),
    url(r'heartbeat', views.heartbeat, name='heartbeat'),
    url(r'out', views.out, name='out'),
    url(r'check', views.check, name='check'),
    url(r'get_qr', views.get_qr, name='get_qr_for_session'),
]