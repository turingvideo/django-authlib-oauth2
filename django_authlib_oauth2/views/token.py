from authlib.integrations.django_oauth2 import RevocationEndpoint
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from ..server import server


@csrf_exempt
@require_POST
def issue(request):
    return server.create_token_response(request)


@csrf_exempt
@require_POST
def revoke(request):
    return server.create_endpoint_response(RevocationEndpoint.ENDPOINT_NAME, request)
