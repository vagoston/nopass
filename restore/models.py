# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models


# Create your models here.
class Shard(models.Model):
    id =  models.AutoField(primary_key=True)
    owner = models.CharField(max_length=200)
    index = models.IntegerField()
    esk = models.CharField(max_length=256)
    # iv = models.CharField(max_length=256)
    witness = models.CharField(max_length=200)
    shard = models.CharField(max_length=1000)
    new_key = models.CharField(max_length=200, blank=True, null=True)
