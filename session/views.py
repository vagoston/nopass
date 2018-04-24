from django.http import HttpResponse, HttpResponseForbidden
from django.contrib.auth import logout
from session.auth import SessionBackend, login_required
from django.shortcuts import render, render_to_response
from django.http import HttpResponseRedirect
from session.models import MyUser
from .forms import LoginForm, RegisterForm, HeartBeatForm
from django.contrib.sessions.backends.db import SessionStore
import qrcode
from io import BytesIO
from crypto.helpers import check_signature
from django.views.decorators.csrf import csrf_exempt
import logging

@csrf_exempt   
def heartbeat(request):
    # if this is a POST request we need to process the form data
    if request.method == 'POST':
        # create a form instance and populate it with data from the request:
        form = HeartBeatForm(request.POST)
        # check whether it's valid:
        if form.is_valid():
            pk_hash = form.cleaned_data['pk_hash']
            user = MyUser.objects.get(pk=hash(pk_hash))
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

@csrf_exempt   
def session_login(request):
    if not request.session.session_key:
        request.session.save()
    session_id = request.session.session_key
    return render(request, 'session.html', {'session_id': session_id})

@csrf_exempt   
def register(request):
    # if this is a POST request we need to process the form data
    if request.method == 'POST':
        # create a form instance and populate it with data from the request:
        form = RegisterForm(request.POST)
        # check whether it's valid:
        if form.is_valid():
            logging.debug("form is valid")
            pk = form.cleaned_data['pk'] + "\n"
            email_hash = hash(form.cleaned_data['email'])
            if check_signature(form.cleaned_data['jc'], form.cleaned_data['signature'], pk):
                MyUser.objects.create_user(email_hash, pk,
                                           form.cleaned_data['jc'], form.cleaned_data['length'])
                return HttpResponse('Done')
            else:
                logging.debug("Signature check failed")
        else:
            logging.debug("Invalid form: %s", str(form))
    # if a GET (or any other method) we'll create a blank form
    else:
        form = RegisterForm()

    return render(request, 'login.html', {'form': form})

@csrf_exempt   
def login_form(request):
    # if this is a POST request we need to process the form data
    if request.method == 'POST':
        # create a form instance and populate it with data from the request:
        form = LoginForm(request.POST)
        # check whether it's valid:
        if form.is_valid():
            logging.debug("Form is valid")
            pk_hash = form.cleaned_data['pk_hash']
            session_id = form.cleaned_data['session_id']
            old_jc = form.cleaned_data['old_jc']
            new_jc = form.cleaned_data['new_jc']
            signature = form.cleaned_data['signature']
            logging.debug("Authenticating")
            user = SessionBackend.authenticate(session_id, pk_hash=hash(pk_hash), signature=signature, old_jc=old_jc, new_jc=new_jc)
            if user:
                logging.debug("Successful")
                remote_session = SessionStore(session_key=session_id)
                remote_session['user_id'] = user.pk
                remote_session.save()
            return HttpResponse('OK')
        else:
            logging.debug("Form is invalid")

    # if a GET (or any other method) we'll create a blank form
    else:
        form = LoginForm()

    return render(request, 'login.html', {'form': form})

def redirect(request):
    user_id = request.session.get('user_id')
    logging.debug(str(user_id))
    if user_id:
        request.session['user_id'] = None
        user = MyUser.objects.get(pk=user_id)
        SessionBackend.session_login(request, user)
        logging.debug("Logged in")
        return render(request, 'redirect_top.html', {'redirect_url':'session/check'})
    else:
        return render_to_response('refresh.html')

def out(request):
    logout(request)
    return HttpResponse()


@login_required
def check(request):
    session_id = request.session.session_key
    if not session_id:
        return HttpResponse()
    return HttpResponse(session_id)