import logging
from authlib.oauth2.rfc6749.util import scope_to_list, list_to_scope
from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http.response import Http404
from django.shortcuts import render
from django.views import View

from ..models import UserConsent, now_timestamp
from ..server import server

logger = logging.getLogger(__name__)


class AuthorizeView(LoginRequiredMixin, View):
    template_name = 'registration/authorize.html'

    def get(self, request, *args, **kwargs):
        try:
            grant = server.validate_consent_request(request, end_user=request.user)
        except Exception as e:
            logger.warning(e)
            raise Http404()

        scope = grant.request.scope
        if client_has_user_consent(grant.client, request.user, scope):
            # skip consent and granted
            return server.create_authorization_response(request, grant_user=request.user)

        context = dict(grant=grant, user=request.user, scopes=set(scope_to_list(scope)))
        return render(request, self.template_name, context)

    def post(self, request, *args, **kwargs):
        if not is_user_consented(request):
            # denied by resource owner
            return server.create_authorization_response(request, grant_user=None)

        try:
            grant = server.validate_consent_request(request, end_user=request.user)
        except Exception as e:
            logger.warning(e)
            raise Http404()

        scope_list = request.POST.getlist('scope_list')
        set_client_user_consent(grant.client, request.user, list_to_scope(scope_list))

        # granted by resource owner
        return server.create_authorization_response(request, grant_user=request.user)


def client_has_user_consent(client, user, scope):
    try:
        uc = UserConsent.objects.get(client=client, user=user)
        return uc.contains_scope(scope) and not uc.is_expired()
    except UserConsent.DoesNotExist:
        return False


def set_client_user_consent(client, user, scope):
    given_at = now_timestamp()
    expires_in = getattr(settings, 'OAUTH2_SKIP_CONSENT_EXPIRES_IN', 86400)

    uc, created = UserConsent.objects.get_or_create(
        client=client, user=user,
        defaults={
            'given_at': given_at,
            'expires_in': expires_in,
            'scope': scope,
        },
    )

    if not created:
        uc.given_at = given_at
        uc.expires_in = expires_in
        uc.scope = scope
        uc.save()


def is_user_consented(request):
    return request.POST.get('action') == 'consent'
