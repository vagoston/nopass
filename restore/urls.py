from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'claim', views.claim, name='claim'),
    url(r'upload', views.upload, name='upload'),
]