from django import forms


class LoginForm(forms.Form):
    session_id = forms.CharField(label='Session ID', max_length=100)
    pk = forms.CharField(label='Public key', max_length=1023)
    signature = forms.CharField(label='Signature', max_length=1023)


class RegisterForm(forms.Form):
    pk = forms.CharField(label='Public key', max_length=1023)
