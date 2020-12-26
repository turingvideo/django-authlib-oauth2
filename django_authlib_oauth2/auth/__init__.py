from django.middleware.csrf import rotate_token as rotate_csrf_token
from django.contrib.auth.signals import user_logged_in
from ..models import Client
from ..server import server

TOKEN_COOKIE_NAME = 'token'

internal_client = Client(client_id='turing')
internal_grant_type = 'password'


def login(request, user, backend=None, expires_in=None):
    if user is None:
        user = request.user

    token = server.generate_token(internal_grant_type, internal_client, user=user, expires_in=expires_in)

    rotate_csrf_token(request)
    user_logged_in.send(sender=user.__class__, request=request, user=user)

    return token
