from django import forms


class LoginForm(forms.Form):
    session_id = forms.CharField(label='Session ID', max_length=100)
    pk = forms.CharField(label='Public key', max_length=1023)
    signature = forms.CharField(label='Signature', max_length=1023)
    jc = forms.CharField(label='Jump code', max_length=256)


class RegisterForm(forms.Form):
    pk = forms.CharField(label='Public key', max_length=1023)
    signature = forms.CharField(label='Jump code hash', max_length=1023)
    jc = forms.CharField(label='Jump code', max_length=256)


class HeartBeatForm(forms.Form):
    pk = forms.CharField(label='Public key', max_length=1023)
    old_jc = forms.CharField(label='Previous jump code', max_length=256)
    new_jc = forms.CharField(label='Jump code', max_length=256)
    signature = forms.CharField(label='Signature', max_length=1023)
