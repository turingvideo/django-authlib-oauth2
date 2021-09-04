import json
from datetime import timedelta
from django.conf import settings
from django.contrib.auth import views as auth_views
from django.http import HttpResponseRedirect, HttpResponse
from django.utils import timezone
from ..resource_server import require_oauth, require_oauth_user
from ..auth import TOKEN_COOKIE_NAME, login as token_auth_login

REMEMBER_ME_EXPIRES_IN = settings.SESSION_COOKIE_AGE


class LoginView(auth_views.LoginView):
    redirect_authenticated_user = True
    session_enabled = True

    def form_valid(self, form):
        """Security check complete. Log the user in."""
        remember_me = form.data.get('remember_me')

        if self.session_enabled:
            self.request.session.set_expiry(None if remember_me else 0)
            return super(LoginView, self).form_valid(form)

        expires_in = REMEMBER_ME_EXPIRES_IN if remember_me else None
        token = token_auth_login(self.request, form.get_user(), expires_in=expires_in)
        expiration = (timezone.now() + timedelta(seconds=token['expires_in']))
        response = HttpResponseRedirect(self.get_success_url())
        response.set_cookie(
            TOKEN_COOKIE_NAME,
            value=str(token['access_token']),
            expires=expiration,
            httponly=True,
        )
        return response


@require_oauth('profile')
@require_oauth_user
def profile(request):
    user = request.user
    userinfo = {
        'sub': user.pk,
        'username': user.username,
        'groups': [g.name for g in user.groups.all()],
    }
    return HttpResponse(json.dumps(userinfo), content_type='application/json')
