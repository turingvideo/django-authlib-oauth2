from django.contrib.auth import authenticate
from authlib.oauth2.rfc6749 import grants
from authlib.oidc.core import OpenIDCode as _OpenIDCode, UserInfo

from .models import Token, AuthorizationCode


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):

    # TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post']

    def save_authorization_code(self, code, request):
        # openid request MAY have "nonce" parameter
        nonce = request.data.get('nonce')
        client = request.client
        auth_code = AuthorizationCode(
            code=code,
            client_id=client.client_id,
            redirect_uri=request.redirect_uri,
            response_type=request.response_type,
            scope=request.scope,
            user=request.user,
            nonce=nonce,
        )
        auth_code.save()
        return auth_code

    def query_authorization_code(self, code, client):
        try:
            item = AuthorizationCode.objects.get(code=code, client_id=client.client_id)
        except AuthorizationCode.DoesNotExist:
            return None

        if not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        authorization_code.delete()

    def authenticate_user(self, authorization_code):
        return authorization_code.user


class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):

    def authenticate_user(self, username, password):
        request = getattr(self.request, 'integration_request', None)
        return authenticate(request=request, username=username, password=password)


class RefreshTokenGrant(grants.RefreshTokenGrant):
    INCLUDE_NEW_REFRESH_TOKEN = True

    def authenticate_refresh_token(self, refresh_token):
        try:
            item = Token.objects.get(refresh_token=refresh_token)
            if item.is_refresh_token_active():
                return item
        except Token.DoesNotExist:
            return None

    def authenticate_user(self, credential):
        return credential.user

    def revoke_old_credential(self, credential):
        credential.revoked = True
        credential.save()


class OpenIDCode(_OpenIDCode):

    def __init__(self, require_nonce=False, jwt_config=None):
        self.require_nonce = require_nonce
        self.jwt_config = jwt_config

    def exists_nonce(self, nonce, request):
        try:
            AuthorizationCode.objects.get(
                client_id=request.client_id, nonce=nonce
            )
            return True
        except AuthorizationCode.DoesNotExist:
            return False

    def get_jwt_config(self, grant):  # pragma: no cover
        """Get the JWT configuration for OpenIDCode extension. The JWT
        configuration will be used to generate ``id_token``.

            {
                'key': '',
                'alg': '',
                'iss': '',
                'exp': 3600
            }

        :param grant: AuthorizationCodeGrant instance
        :return: dict
        """
        return self.jwt_config

    def generate_user_info(self, user, scope):  # pragma: no cover
        user_info = UserInfo(sub=str(user.pk), name=self.get_user_name(user))
        if 'email' in scope:
            user_info['email'] = user.email
        return user_info

    def get_user_name(self, user):
        if hasattr(user, 'name'):
            return user.name
        if hasattr(user, 'display_name'):
            return user.display_name
