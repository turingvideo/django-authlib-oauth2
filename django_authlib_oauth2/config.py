from django.conf import settings

authorization_server_config = getattr(settings, 'AUTHLIB_OAUTH2_PROVIDER', {})
authorization_server_jwt_config = {
    'key': (authorization_server_config.get('jwt_secret_key') or '').replace('\\n', '\n'),
    'alg': authorization_server_config.get('jwt_alg'),
    'iss': authorization_server_config.get('jwt_issuer'),
    'exp': 3600,
}


resource_server_config = getattr(settings, 'AUTHLIB_RESOURCE_SERVER', {})
resource_server_jwt_config = {
    'public_key': (resource_server_config.get('jwt_public_key') or '').replace('\\n', '\n'),
    'iss': authorization_server_config.get('jwt_issuer'),
}
