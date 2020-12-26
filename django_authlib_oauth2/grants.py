from django.contrib.auth import get_user_model
from authlib.oauth2.rfc6749 import grants

from .models import Token, AuthorizationCode

User = get_user_model()


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):

    # TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post']

    def save_authorization_code(self, code, request):
        client = request.client
        auth_code = AuthorizationCode(
            code=code,
            client_id=client.client_id,
            redirect_uri=request.redirect_uri,
            response_type=request.response_type,
            scope=request.scope,
            user=request.user,
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
        try:
            user = User.objects.get(username=username)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None


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
