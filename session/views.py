from django.http import HttpResponse


def index(request):
    if not request.session.session_key:
        request.session.save()
    session_id = request.session.session_key
    return HttpResponse(session_id)


def out(request):
    request.session.flush()
    return HttpResponse()