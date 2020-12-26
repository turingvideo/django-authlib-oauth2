import time
from django.conf import settings
from django.db import models
from authlib.oauth2.rfc6749 import AuthorizationCodeMixin, ClientMixin, TokenMixin
from authlib.oauth2.rfc6749.util import scope_to_list, list_to_scope


def now_timestamp():
    return int(time.time())


class Client(models.Model, ClientMixin):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )
    client_id = models.CharField(max_length=48, unique=True, db_index=True)
    client_secret = models.CharField(max_length=48, blank=True)
    client_name = models.CharField(max_length=120)
    redirect_uris = models.TextField(blank=True, default='')
    default_redirect_uri = models.TextField(blank=True, default='')
    scope = models.TextField(blank=True, default='')
    response_type = models.TextField(blank=True, default='')
    grant_type = models.TextField(blank=True, default='')
    token_endpoint_auth_method = models.CharField(max_length=120, blank=True, default='')

    # you can add more fields according to your own need
    # check https://tools.ietf.org/html/rfc7591#section-2

    logo = models.URLField(blank=True, default='')
    website = models.URLField(blank=True, default='')

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        return self.default_redirect_uri

    def get_allowed_scope(self, scope):
        if not scope:
            return ''
        allowed = set(scope_to_list(self.scope))
        return list_to_scope([s for s in scope.split() if s in allowed])

    def check_redirect_uri(self, redirect_uri):
        if redirect_uri == self.default_redirect_uri:
            return True
        return redirect_uri in self.redirect_uris

    def has_client_secret(self):
        return bool(self.client_secret)

    def check_client_secret(self, client_secret):
        return self.client_secret == client_secret

    def check_token_endpoint_auth_method(self, method):
        allowed = self.token_endpoint_auth_method.split()
        return method in allowed

    def check_response_type(self, response_type):
        allowed = self.response_type.split()
        return response_type in allowed

    def check_grant_type(self, grant_type):
        allowed = self.grant_type.split()
        return grant_type in allowed


class Token(models.Model, TokenMixin):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )
    client_id = models.CharField(max_length=48, db_index=True)
    token_type = models.CharField(max_length=40)
    access_token = models.CharField(max_length=255, unique=True, null=False)
    refresh_token = models.CharField(max_length=255, db_index=True)
    scope = models.TextField(default='')
    revoked = models.BooleanField(default=False)
    issued_at = models.IntegerField(null=False, default=now_timestamp)
    expires_in = models.IntegerField(null=False, default=0)

    def get_client_id(self):
        return self.client_id

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return self.expires_in

    def get_expires_at(self):
        return self.issued_at + self.expires_in


class AuthorizationCode(models.Model, AuthorizationCodeMixin):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )
    client_id = models.CharField(max_length=48, db_index=True)
    code = models.CharField(max_length=120, unique=True, null=False)
    redirect_uri = models.TextField(default='', null=True)
    response_type = models.TextField(default='')
    scope = models.TextField(default='', null=True)
    auth_time = models.IntegerField(null=False, default=now_timestamp)

    def is_expired(self):
        return self.auth_time + 300 < time.time()

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope or ''

    def get_auth_time(self):
        return self.auth_time
