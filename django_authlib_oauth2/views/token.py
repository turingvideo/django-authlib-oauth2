import json
from authlib.jose import JsonWebKey
from authlib.integrations.django_oauth2 import RevocationEndpoint
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST
from ..server import server, jwt_config


@csrf_exempt
@require_POST
def issue(request):
    return server.create_token_response(request)


@csrf_exempt
@require_POST
def revoke(request):
    return server.create_endpoint_response(RevocationEndpoint.ENDPOINT_NAME, request)


@require_GET
def keys(request):
    key = JsonWebKey.import_key(jwt_config['key'], {'kty': 'RSA'})
    key = key.as_dict(True)
    key_dict = {
        'alg': jwt_config['alg'],
        'e': key['e'],
        'kid': key['kid'],
        'kty': key['kty'],
        'n': key['n'],
        'use': 'sig',
    }
    data = {'keys': [key_dict]}
    return HttpResponse(json.dumps(data), content_type='application/json')
