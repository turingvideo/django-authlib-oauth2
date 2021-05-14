from datetime import datetime
from pytz import UTC
from django import forms
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from . import models


GRANT_TYPES_CHOICES = (
    ('authorization_code', 'Authorization Code'),
    ('password', 'Resource Owner Password'),
    ('refresh_token', 'Refresh Token'),
    ('client_credentials', 'Client Credentials'),
)

RESPONSE_TYPE_CHOICES = (
    ('code', 'code'),
    ('token', 'token'),
)

TOKEN_ENDPOINT_AUTH_METHOD_CHOICES = (
    ('client_secret_basic', 'HTTP Authentication Basic'),
    ('client_secret_post', 'HTTP POST'),
)


class JoinSelectMultiple(forms.SelectMultiple):

    def __init__(self, separator=' ', *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.separator = separator

    def value_from_datadict(self, data, files, name):
        getter = data.get
        if self.allow_multiple_selected:
            try:
                getter = data.getlist
            except AttributeError:
                pass
        val = getter(name)
        return self.separator.join(val)

    def format_value(self, value):
        if isinstance(value, str):
            value = value.split(self.separator)
        return super().format_value(value)


class ClientForm(forms.ModelForm):

    class Meta:
        model = models.Client
        fields = '__all__'
        widgets = {
            'grant_type': JoinSelectMultiple(choices=GRANT_TYPES_CHOICES),
            'response_type': JoinSelectMultiple(choices=RESPONSE_TYPE_CHOICES),
            'token_endpoint_auth_method': JoinSelectMultiple(choices=TOKEN_ENDPOINT_AUTH_METHOD_CHOICES),
        }


@admin.register(models.Client)
class ClientAdmin(admin.ModelAdmin):
    form = ClientForm
    list_display = ('id', 'client_id', 'client_name', 'website')
    raw_id_fields = ('user',)


@admin.register(models.UserConsent)
class UserConsentAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'client', 'scope', 'given_at_time', 'expires_in', 'is_expired')
    raw_id_fields = ('user', 'client')

    @admin.display(ordering='given_at')
    def given_at_time(self, item):
        return item.given_at_time

    @admin.display(boolean=True)
    def is_expired(self, item):
        return item.is_expired()


@admin.register(models.Token)
class TokenAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'client_id', 'scope', 'issued_at_time', 'expires_in', 'is_expired', 'revoked')
    search_fields = ['client_id'] + ['user__' + f for f in UserAdmin.search_fields]

    @admin.display(boolean=True)
    def is_expired(self, item):
        return item.is_expired()


@admin.register(models.AuthorizationCode)
class AuthorizationCodeAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'client_id', 'time')
    search_fields = ['client_id'] + ['user__' + f for f in UserAdmin.search_fields]

    def time(self, item):
        return datetime.fromtimestamp(item.auth_time).replace(tzinfo=UTC)
