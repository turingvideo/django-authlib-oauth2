from django.conf import settings
from django.utils.module_loading import import_string
from authlib.oauth2 import OAuth2Request
from authlib.integrations.django_oauth2 import (
    AuthorizationServer as _AuthorizationServer,
    RevocationEndpoint,
)
from authlib.integrations.django_helpers import create_oauth_request

from . import models, grants
from .authlib_future import jwt


class AuthorizationServer(_AuthorizationServer):

    def __init__(self, client_model, token_model):
        self.config = getattr(settings, 'AUTHLIB_OAUTH2_PROVIDER', {})

        default_token_generator = self.config.get('default_token_generator')
        if default_token_generator == 'jwt':
            alg = self.config.get('jwt_alg')
            secret_key = self.config.get('jwt_secret_key')
            issuer = self.config.get('jwt_issuer')
            extra_token_data = self.config.get('jwt_extra_token_data')
            if not alg or not secret_key:
                raise RuntimeError('"jwt_alg" and "jwt_secret_key" are required.')
            get_extra_token_data = create_extra_token_data_getter(extra_token_data)
            default_token_generator = jwt.JWTBearerTokenGenerator(
                secret_key, alg=alg, issuer=issuer,
                get_extra_token_data=get_extra_token_data,
            )

            def not_save_oauth2_token(*args, **kwargs):
                pass
            self.save_oauth2_token = not_save_oauth2_token

        super(AuthorizationServer, self).__init__(
            client_model, token_model,
            generate_token=default_token_generator,
        )

    def create_oauth2_request(self, request):
        content_type = request.content_type
        if content_type:
            # In case of 'application/json; indent=4'
            content_type = content_type.split(';')[0]
        use_json = 'application/json' == content_type
        return create_oauth_request(request, OAuth2Request, use_json=use_json)


def create_extra_token_data_getter(extra_token_data):
    if callable(extra_token_data):
        return extra_token_data

    if isinstance(extra_token_data, str):
        return import_string(extra_token_data)
    elif extra_token_data is True:
        def get_extra_token_data(user, scope):
            return {
                'username': user.username,
            }
        return get_extra_token_data


server = AuthorizationServer(models.Client, models.Token)

server.register_grant(grants.AuthorizationCodeGrant)
server.register_grant(grants.PasswordGrant)
server.register_grant(grants.RefreshTokenGrant)

server.register_endpoint(RevocationEndpoint)
