from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend as _ModelBackend
from django.core.validators import ValidationError, validate_email

UserModel = get_user_model()


class ModelBackend(_ModelBackend):
    """
    Authenticates against settings.AUTH_USER_MODEL, with username or email.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD)
        try:
            user = self.lookup_user(username)
        except UserModel.DoesNotExist:
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a nonexistent user (#20760).
            UserModel().set_password(password)
        else:
            if user.check_password(password) and self.user_can_authenticate(user):
                return user

    def lookup_user(self, key):
        for lookup in self.get_user_lookups():
            try:
                user = lookup(key)
                if user is not None:
                    return user
            except UserModel.DoesNotExist:
                continue
        raise UserModel.DoesNotExist()

    def get_user_lookups(self):
        return [
            self.lookup_user_by_email,
            self.lookup_user_by_username,
        ]

    def lookup_user_by_username(self, username):
        return UserModel._default_manager.get_by_natural_key(username)

    def lookup_user_by_email(self, email):
        try:
            validate_email(email)
        except ValidationError:
            return
        return UserModel._default_manager.get(**{UserModel.EMAIL_FIELD: email})
