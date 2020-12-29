import functools
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils.functional import SimpleLazyObject
from authlib.oauth2.rfc6749 import UnsupportedTokenTypeError
from authlib.integrations.django_oauth2 import ResourceProtector as _ResourceProtector, BearerTokenValidator
from authlib.integrations.django_oauth2.resource_protector import return_error_response

from .authlib_future.jwt import JWTBearerTokenValidator as _JWTBearerTokenValidator, JWTBearerToken
from .models import Token

UserModel = get_user_model()


class JWTBearerTokenValidator(_JWTBearerTokenValidator):

    def request_invalid(self, request):
        return False

    def token_revoked(self, token):
        return False


def get_user(request, token):
    if not hasattr(request, '_cached_token_user'):
        user = None
        if isinstance(token, Token):
            user = token.user
        elif isinstance(token, JWTBearerToken):
            user = UserModel.objects.get(pk=token['sub'])
        request._cached_token_user = user
    return request._cached_token_user


class ResourceProtector(_ResourceProtector):

    def acquire_token(self, request, scope=None, operator='AND'):
        token = super(ResourceProtector, self).acquire_token(request, scope=scope, operator=operator)
        request.user = SimpleLazyObject(lambda: get_user(request, token))
        return token


def build_resource_protector():
    config = getattr(settings, 'AUTHLIB_RESOURCE_SERVER', {})
    jwt_public_key = config.get('jwt_public_key')
    protector = ResourceProtector()
    if jwt_public_key:
        jwt_issuer = config.get('jwt_issuer')
        jwt_public_key = jwt_public_key.replace('\\n', '\n')
        protector.register_token_validator(JWTBearerTokenValidator(
            jwt_public_key, issuer=jwt_issuer, sub_essential=False,
        ))
    else:
        protector.register_token_validator(BearerTokenValidator(Token))
    return protector


def require_client_credentials(required=False):
    def wrapper(f):
        @functools.wraps(f)
        def decorated(request, *args, **kwargs):
            token = getattr(request, 'oauth_token', None)
            if not token:
                raise RuntimeError('Token is empty. Did you missing require_oauth() beforehand?')

            if required != (token['grant_type'] == 'client_credentials'):
                return return_error_response(UnsupportedTokenTypeError('Restricted to %s access' % ('client' if required else 'user')))

            return f(request, *args, **kwargs)
        return decorated
    return wrapper


require_oauth = build_resource_protector()
require_oauth_client = require_client_credentials(True)
require_oauth_user = require_client_credentials(False)
