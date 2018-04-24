from django import forms


class LoginForm(forms.Form):
    session_id = forms.CharField(label='Session ID', max_length=100)
    pk_hash = forms.CharField(label='Public key hash')
    signature = forms.CharField(label='Signature', max_length=2048)
    old_jc = forms.IntegerField(label='old Jump code')
    new_jc = forms.IntegerField(label='new Jump code')


class RegisterForm(forms.Form):
    email = forms.CharField(label='Email address')
    pk = forms.CharField(label='Public key', max_length=2048)
    signature = forms.CharField(label='Jump code hash', max_length=2048)
    jc = forms.IntegerField(label='Jump code')
    lenght = forms.IntegerField(label='Private key length')


class HeartBeatForm(forms.Form):
    pk_hash = forms.CharField(label='Public key hash')
    old_jc = forms.IntegerField(label='Previous jump code')
    new_jc = forms.IntegerField(label='Jump code')
    signature = forms.CharField(label='Signature', max_length=2048)
