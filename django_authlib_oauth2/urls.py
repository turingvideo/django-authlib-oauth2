from django.urls import re_path

from .views import token, user
from .views.authorize import AuthorizeView
from .views.user import LoginView

urlpatterns = [
    re_path(r'^token$', token.issue),
    re_path(r'^revoke$', token.revoke),
    re_path(r'^profile$', user.profile),
    re_path(r'^login$', LoginView.as_view()),
    re_path(r'^authorize$', AuthorizeView.as_view()),
]
