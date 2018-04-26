from django import forms


class ShardUploadForm(forms.Form):
    pk = forms.CharField(label='Public key', max_length=2048)
    wpk = forms.CharField(label='Witness public key', max_length=2048)
    index = forms.IntegerField(label='index of shard')
    esk = forms.CharField(label='Encrypted secret key', max_length=1024)
    # iv = forms.CharField(label='iv', max_length=256)
    shard = forms.CharField(label='encoded shard', max_length=2048)
    new_pk = forms.CharField(label='new pk', max_length=2048, required=False)
    signature = forms.CharField(label='signature', max_length=2048)


class ShardClaimForm(forms.Form):
    pk = forms.CharField(label='Public key', max_length=2048)
    wpk = forms.CharField(label='Witness public key', max_length=2048)
    signature = forms.CharField(label='signature', max_length=2048)
    new_pk = forms.CharField(label='new pk', max_length=2048, required=False)
