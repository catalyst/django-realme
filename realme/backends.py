from django.contrib.auth.models import User
from django.conf import settings


class SamlBackend(object):

    def authenticate(self, request, saml2_auth=None):
        """
        Get or create user from a OneLogin_Saml2_Auth object.
        """
        username = saml2_auth.get_nameid()
        user, _ = User.objects.get_or_create(username=username)
        attrs = saml2_auth.get_attributes()
        if attrs:
            request.session['logon_attributes_token'] = attrs.get('logon_attributes_token', [''])[0]
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
