# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import logging
from django.http import HttpResponse
from crypto.helpers import check_signature, full_hash
from .forms import ShardUploadForm
from django.views.decorators.csrf import csrf_exempt
from restore.models import Shard


@csrf_exempt
def upload(request):
    # create a form instance and populate it with data from the request:
    form = ShardUploadForm(request.POST)
    # check whether it's valid:
    if form.is_valid():
        logging.debug("form is valid")
        pk = form.cleaned_data['pk']+ "\n"
        wpk = form.cleaned_data['wpk'] + "\n"
        esk = form.cleaned_data['esk']
        index = form.cleaned_data['index']
        shard = form.cleaned_data['shard']
        data = pk + str(index) + wpk + esk + shard
        if check_signature(data, form.cleaned_data['signature'], pk):
            Shard.objects.create(
                pk=full_hash(pk), 
                wpk=full_hash(wpk),
                index=index,  
                esk=esk,
                # iv=iv,
                shard=shard)
        else:
            logging.debug("Signature check failed")
        return HttpResponse('Done')
    else:
        logging.debug("Invalid form: %s", str(form))

@csrf_exempt
def claim(request):
    # create a form instance and populate it with data from the request:
    form = ShardUploadForm(request.POST)
    # check whether it's valid:
    if form.is_valid():
        logging.debug("form is valid")
        pk = form.cleaned_data['pk'] + "\n"
        wpk = form.cleaned_data['wpk'] + "\n"
        npk = form.cleaned_data.get('new_pk')
        if npk:
            data = pk + wpk
            if check_signature(data, wpk):
                sh = Shard.objects.get(pk = full_hash(pk), wpk =  full_hash(wpk))
                return str(sh.index) + sh.shard
            else:
                logging.debug("Signature check failed")
        else:
            data = pk + wpk
            if check_signature(data, form.cleaned_data['signature'], npk):
                sh = Shard.objects.get(pk = full_hash(pk), wpk = full_hash(wpk))
                return str(sh.index) + sh.shard
            else:
                logging.debug("Signature check failed")
        return HttpResponse('Done')
    else:
        logging.debug("Invalid form: %s", str(form))
