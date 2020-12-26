from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render
from django.views import View
from ..server import server


class AuthorizeView(LoginRequiredMixin, View):
    template_name = 'registration/authorize.html'

    def get(self, request, *args, **kwargs):
        grant = server.validate_consent_request(request, end_user=request.user)
        context = dict(grant=grant, user=request.user)
        return render(request, self.template_name, context)

    def post(self, request, *args, **kwargs):
        if is_user_confirmed(request):
            # granted by resource owner
            return server.create_authorization_response(request, grant_user=request.user)

        # denied by resource owner
        return server.create_authorization_response(request, grant_user=None)


def is_user_confirmed(request):
    return request.POST.get('confirm')
