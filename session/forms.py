from django import forms


class SessionForm(forms.Form):
    session_id = forms.CharField(label='Session ID', max_length=100)
    user_id = forms.IntegerField(label='User ID')
