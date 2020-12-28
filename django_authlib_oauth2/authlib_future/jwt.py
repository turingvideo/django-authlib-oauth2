import time
from authlib.common.encoding import to_native
from authlib.jose import jwt, JoseError, JWTClaims
from authlib.oauth2.rfc6749 import TokenMixin
from authlib.oauth2.rfc6750 import BearerTokenValidator


class JWTBearerTokenGenerator(object):
    """A JSON Web Token formatted bearer token generator for jwt-bearer grant type.
    This token generator can be registered into authorization server::
        authorization_server.register_token_generator(
            'urn:ietf:params:oauth:grant-type:jwt-bearer',
            JWTBearerTokenGenerator(private_rsa_key),
        )
    In this way, we can generate the token into JWT format. And we don't have to
    save this token into database, since it will be short time valid. Consider to
    rewrite ``JWTBearerGrant.save_token``::
        class MyJWTBearerGrant(JWTBearerGrant):
            def save_token(self, token):
                pass
    :param secret_key: private RSA key in bytes, JWK or JWK Set.
    :param issuer: a string or URI of the issuer
    :param alg: ``alg`` to use in JWT
    """
    DEFAULT_EXPIRES_IN = 3600

    def __init__(self, secret_key, issuer=None, alg='RS256', get_extra_token_data=None):
        self.secret_key = secret_key
        self.issuer = issuer
        self.alg = alg
        self.get_extra_token_data = get_extra_token_data

    @staticmethod
    def get_allowed_scope(client, scope):
        if scope:
            scope = client.get_allowed_scope(scope)
        return scope

    @staticmethod
    def get_user_id(user):
        if hasattr(user, 'get_user_id'):
            return user.get_user_id()
        return user.id

    def get_token_data(self, grant_type, client, user=None, scope=None, expires_in=None):
        scope = self.get_allowed_scope(client, scope)
        if not expires_in:
            expires_in = self.DEFAULT_EXPIRES_IN
        issued_at = int(time.time())
        data = {
            'scope': scope,
            'grant_type': grant_type,
            'iat': issued_at,
            'exp': issued_at + expires_in,
            'client_id': client.get_client_id(),
        }
        if self.issuer:
            data['iss'] = self.issuer
        if user:
            data['sub'] = self.get_user_id(user)
        if self.get_extra_token_data:
            extra = self.get_extra_token_data(user, scope)
            if extra:
                data.update(extra)
        return data

    def generate(self, grant_type, client, user=None, scope=None, expires_in=None):
        """Generate a bearer token for OAuth 2.0 authorization token endpoint.
        :param client: the client that making the request.
        :param grant_type: current requested grant_type.
        :param user: current authorized user.
        :param expires_in: if provided, use this value as expires_in.
        :param scope: current requested scope.
        :return: Token dict
        """
        if not expires_in:
            expires_in = self.DEFAULT_EXPIRES_IN
        token_data = self.get_token_data(grant_type, client, user, scope, expires_in)
        access_token = jwt.encode({'alg': self.alg}, token_data, key=self.secret_key, check=False)
        token = {
            'token_type': 'Bearer',
            'access_token': to_native(access_token),
            'expires_in': expires_in,
        }
        if scope:
            token['scope'] = scope
        return token

    def __call__(self, grant_type, client, user=None, scope=None,
                 expires_in=None, include_refresh_token=True):
        # there is absolutely no refresh token in JWT format
        return self.generate(grant_type, client, user, scope, expires_in)


class JWTBearerToken(TokenMixin, JWTClaims):

    def check_client(self, client):
        return self['client_id'] == client.get_client_id()

    def get_scope(self):
        return self.get('scope')

    def get_expires_in(self):
        return self['exp'] - self['iat']

    def get_expires_at(self):
        return self['exp']

    def is_expired(self):
        return self['exp'] < time.time()

    def is_revoked(self):
        return False


class JWTBearerTokenValidator(BearerTokenValidator):
    TOKEN_TYPE = 'bearer'
    token_cls = JWTBearerToken

    def __init__(self, public_key, sub_essential=True, issuer=None, realm=None, **extra_attributes):
        super(JWTBearerTokenValidator, self).__init__(realm, **extra_attributes)
        self.public_key = public_key
        claims_options = {
            # 'sub': {'essential': True},
            'exp': {'essential': True},
            'client_id': {'essential': True},
            'grant_type': {'essential': True},
        }
        if sub_essential:
            claims_options['sub'] = {'essential': True}
        if issuer:
            claims_options['iss'] = {'essential': True, 'value': issuer}
        self.claims_options = claims_options

    def authenticate_token(self, token_string):
        try:
            claims = jwt.decode(
                token_string, self.public_key,
                claims_options=self.claims_options,
                claims_cls=self.token_cls,
            )
            claims.validate()
            return claims
        except JoseError:
            return None
