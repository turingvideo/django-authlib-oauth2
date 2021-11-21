from django.utils.module_loading import import_string
from authlib.oauth2 import OAuth2Request
from authlib.oauth2.rfc6749.grants import ClientCredentialsGrant
from authlib.integrations.django_oauth2 import (
    AuthorizationServer as _AuthorizationServer,
    RevocationEndpoint,
)
from authlib.integrations.django_helpers import create_oauth_request

from . import models, grants
from .authlib_future import jwt
from .config import (
    authorization_server_config,
    authorization_server_jwt_config as jwt_config,
)

jwt_key_provider = None
if 'jwt_key_provider' in authorization_server_config:
    jwt_key_provider = import_string(authorization_server_config['jwt_key_provider'])


class AuthorizationServer(_AuthorizationServer):

    def __init__(self, client_model, token_model):
        self.config = authorization_server_config

        default_token_generator = self.config.get('default_token_generator')
        if default_token_generator == 'jwt':
            token_generator_class = self.config.get('default_token_generator_class')
            if token_generator_class:
                token_generator_class = import_string(token_generator_class)
            else:
                token_generator_class = jwt.JWTBearerTokenGenerator
            alg = jwt_config['alg']
            secret_key = jwt_config['key']
            issuer = jwt_config['iss']
            extra_token_data = self.config.get('jwt_extra_token_data')
            if not alg or not secret_key:
                raise RuntimeError('"jwt_alg" and "jwt_secret_key" are required.')
            get_extra_token_data = create_extra_token_data_getter(extra_token_data)
            default_token_generator = token_generator_class(
                jwt_key_provider or secret_key,
                alg=alg, issuer=issuer,
                get_extra_token_data=get_extra_token_data,
            )

            def not_save_oauth2_token(*args, **kwargs):
                pass
            self.save_oauth2_token = not_save_oauth2_token

        super(AuthorizationServer, self).__init__(
            client_model, token_model,
            generate_token=default_token_generator,
        )

        client_auth_class = self.config.get('client_auth_class')
        if client_auth_class:
            client_auth_class = import_string(client_auth_class)
            self._client_auth = client_auth_class()

    def create_oauth2_request(self, request):
        content_type = request.content_type
        if content_type:
            # In case of 'application/json; indent=4'
            content_type = content_type.split(';')[0]
        use_json = 'application/json' == content_type
        oauth2_request = create_oauth_request(request, OAuth2Request, use_json=use_json)
        oauth2_request.integration_request = request
        return oauth2_request


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

server.register_grant(grants.AuthorizationCodeGrant, [grants.OpenIDCode(require_nonce=False, jwt_config=jwt_config)])
server.register_grant(grants.PasswordGrant)
server.register_grant(grants.RefreshTokenGrant)
server.register_grant(ClientCredentialsGrant)

server.register_endpoint(RevocationEndpoint)
