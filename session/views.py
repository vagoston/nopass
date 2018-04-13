from django.http import HttpResponse, HttpResponseForbidden
from django.contrib.auth import logout
from session.auth import SessionBackend, login_required
from django.shortcuts import render
from django.http import HttpResponseRedirect
from session.models import MyUser
from .forms import LoginForm, RegisterForm, HeartBeatForm
from django.contrib.sessions.backends.db import SessionStore
import qrcode
from io import BytesIO
from crypto.helpers import check_signature


def heartbeat(request):
    # if this is a POST request we need to process the form data
    if request.method == 'POST':
        # create a form instance and populate it with data from the request:
        form = HeartBeatForm(request.POST)
        # check whether it's valid:
        if form.is_valid():
            pk_hash = form.cleaned_data['pk_hash']
            user = MyUser.objects.get(pk=int(pk_hash))
            if check_signature(form.cleaned_data['new_jc'], form.cleaned_data['signature'], user.public_key):
                if not user.is_compromised:
                    if user.jump_code == form.cleaned_data['old_jc']:
                        user.jump_code = form.cleaned_data['new_jc']
                        user.save()
                        return HttpResponse('Done')
                    else:
                        user.is_compromised = True
                        user.save()
                        return HttpResponseForbidden()
            return HttpResponseForbidden()

    # if a GET (or any other method) we'll create a blank form
    else:
        form = HeartBeatForm()

    return render(request, 'login.html', {'form': form})


def index(request):
    return HttpResponse()


def get_qr(request):

    with BytesIO() as image:
        qrcode.make(request.session.session_key).get_image().save(image, 'PNG')
        return HttpResponse(image.getvalue(), content_type="image/png")


def session_login(request):
    if not request.session.session_key:
        request.session.save()
    session_id = request.session.session_key
    pk_hash = request.session.get('pk_hash')
    signature = request.session.get('signature')
    old_jc = request.session.get('old_jc')
    new_jc = request.session.get('new_jc')
    if pk_hash:
        user = SessionBackend.authenticate(request, pk_hash=pk_hash, signature=signature, old_jc=old_jc, new_jc=new_jc)
        if user:
            SessionBackend.session_login(request, user)
            return HttpResponseRedirect('/session/check')
        else:
            return HttpResponseForbidden()
    return render(request, 'session.html', {'session_id': session_id})


def register(request):
    # if this is a POST request we need to process the form data
    if request.method == 'POST':
        # create a form instance and populate it with data from the request:
        form = RegisterForm(request.POST)
        # check whether it's valid:
        if form.is_valid():
            pk = form.cleaned_data['pk']
            email_hash = hash(form.cleaned_data['email'])
            if check_signature(form.cleaned_data['jc'], form.cleaned_data['signature'], pk):
                MyUser.objects.create_user(email_hash, pk,
                                           form.cleaned_data['jc'])
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
            pk_hash = form.cleaned_data['pk_hash']
            remote_session = SessionStore(session_key=form.cleaned_data['session_id'])
            remote_session['pk_hash'] = pk_hash
            remote_session['old_jc'] = form.cleaned_data['old_jc']
            remote_session['new_jc'] = form.cleaned_data['new_jc']
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