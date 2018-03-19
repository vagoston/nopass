from django.http import HttpResponse
from django.contrib.auth import login, logout
from session.auth import SessionBackend
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.http import HttpResponseRedirect
from session.models import MyUser
from .forms import LoginForm, RegisterForm
from django.contrib.sessions.backends.db import SessionStore


def index(request):
    return HttpResponse()


def session_login(request):
    if not request.session.session_key:
        request.session.save()
    session_id = request.session.session_key
    pk = request.session.get('pk')
    signature = request.session.get('signature')
    if pk:
        user = SessionBackend.authenticate(request, pk=pk, signature=signature)
        if user:
            login(request, user)
            return HttpResponseRedirect('/session/check')
    return HttpResponse(session_id)


def register(request):
    # if this is a POST request we need to process the form data
    if request.method == 'POST':
        # create a form instance and populate it with data from the request:
        form = RegisterForm(request.POST)
        # check whether it's valid:
        if form.is_valid():
            MyUser.objects.create_user(form.cleaned_data['pk'])
            return HttpResponse('Done')
    # if a GET (or any other method) we'll create a blank form
    else:
        form = RegisterForm()

    return render(request, 'login.html', {'form': form})


def login_form(request):
    # if this is a POST request we need to process the form data
    if request.method == 'POST':
        # create a form instance and populate it with data from the request:
        form = LoginForm(request.POST)
        # check whether it's valid:
        if form.is_valid():
            remote_session = SessionStore(session_key=form.cleaned_data['session_id'])
            remote_session['pk'] = form.cleaned_data['pk']
            remote_session['signature'] = form.cleaned_data['signature']
            remote_session.save()
            return HttpResponse('Done')

    # if a GET (or any other method) we'll create a blank form
    else:
        form = LoginForm()

    return render(request, 'login.html', {'form': form})


def out(request):
    logout(request)
    return HttpResponse()


@login_required
def check(request):
    session_id = request.session.session_key
    if not session_id:
        return HttpResponse()
    return HttpResponse(session_id)