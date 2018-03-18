from django.http import HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.contrib.auth.models import User
from .forms import SessionForm
from django.contrib.sessions.backends.db import SessionStore


def index(request):
    return HttpResponse()


def session_login(request):
    if not request.session.session_key:
        request.session.save()
    session_id = request.session.session_key
    user_id = request.session.get('user_id')
    if user_id:
        user = User.objects.get(pk=user_id)
        login(request, user)
        return HttpResponseRedirect('/session/check')
    return HttpResponse(session_id)


def login_form(request):
    # if this is a POST request we need to process the form data
    if request.method == 'POST':
        # create a form instance and populate it with data from the request:
        form = SessionForm(request.POST)
        # check whether it's valid:
        if form.is_valid():
            remote_session = SessionStore(session_key=form.cleaned_data['session_id'])
            remote_session['user_id'] = form.cleaned_data['user_id']
            remote_session.save()
            return HttpResponse('Done')

    # if a GET (or any other method) we'll create a blank form
    else:
        form = SessionForm()

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