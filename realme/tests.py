from os.path import abspath, dirname
from urllib.parse import urlsplit

from django.test import TestCase, RequestFactory
from django.test import override_settings
from django.http import QueryDict
from django.conf import settings

from path import Path
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from .views import login
from .bundles import AuthnContextClassRef, Bundle

HERE = Path(dirname(abspath(__file__)))
SAMPLES = HERE/'samples'

class RealMeTestCase(TestCase):

    def test_html_escape(self):
        """
        Compare html escape between Python and Java.
        """
        opaque_token_raw = (SAMPLES/'opaque_token_raw.xml').text()
        from .views import escape_opaque_token
        opaque_token_escaped_python = escape_opaque_token(opaque_token_raw)
        opaque_token_escaped_java = (SAMPLES/'opaque_token_escaped_java.xml').text()
        self.assertEqual(opaque_token_escaped_python, opaque_token_escaped_java)

    def test_bundles_config(self):
        """
        Test customized BUNDLES settings are actually applied.
        """
        for name, conf in settings.BUNDLES.items():
            b = Bundle(name=name, healthcheck=False)  # bundles may not exist
            for key, value in conf.items():
                actual = b.config.get(key)
                self.assertEqual(value, actual, msg='name: {}, key: {}'.format(name, key))


@override_settings(BUNDLE_NAME='MTS')
class LoginViewTests(TestCase):
    """
    Tests for the login view.
    NOTE: These need to be run from inside a project that has the MTS bundle decrypted
    and defined in settings.
    """

    def setUp(self):
        self.factory = RequestFactory(HTTP_HOST='localhost')

    def test_low_strength(self):
        request = self.factory.get('/login/', {'strength': 'low'})
        response = login(request)

        self.assert_redirects_to_mts(response)

        query = self.get_query_dict(response.url)

        self.assertIn('SAMLRequest', query)

        saml_request = self.decode_saml_request(query['SAMLRequest'])

        self.assertIn(
            '<saml:AuthnContextClassRef>{}</saml:AuthnContextClassRef>'.format(AuthnContextClassRef.LowStrength),
            saml_request
        )

    def test_moderate_strength(self):
        request = self.factory.get('/login/', {'strength': 'moderate'})
        response = login(request)

        self.assert_redirects_to_mts(response)

        query = self.get_query_dict(response.url)

        self.assertIn('SAMLRequest', query)

        saml_request = self.decode_saml_request(query['SAMLRequest'])

        self.assertIn(
            '<saml:AuthnContextClassRef>{}</saml:AuthnContextClassRef>'.format(AuthnContextClassRef.ModStrength),
            saml_request
        )

    def test_default_strength(self):
        """
        should default to low strength when the strength parameter isn't provided
        """
        request = self.factory.get('/login/')
        response = login(request)

        self.assert_redirects_to_mts(response)

        query = self.get_query_dict(response.url)

        self.assertIn('SAMLRequest', query)

        saml_request = self.decode_saml_request(query['SAMLRequest'])

        self.assertIn(
            '<saml:AuthnContextClassRef>{}</saml:AuthnContextClassRef>'.format(AuthnContextClassRef.LowStrength),
            saml_request
        )

    def test_invalid_strength(self):
        """
        should default to low strength when the strength parameter isn't a recognized value
        """
        request = self.factory.get('/login/', {'strength': 'high'})
        response = login(request)

        self.assert_redirects_to_mts(response)

        query = self.get_query_dict(response.url)

        self.assertIn('SAMLRequest', query)

        saml_request = self.decode_saml_request(query['SAMLRequest'])

        self.assertIn(
            '<saml:AuthnContextClassRef>{}</saml:AuthnContextClassRef>'.format(AuthnContextClassRef.LowStrength),
            saml_request
        )

    def assert_redirects_to_mts(self, response):
        self.assertEqual(response.status_code, 302)
        url = urlsplit(response.url)
        self.assertEqual(url.netloc, 'mts.realme.govt.nz')
        self.assertEqual(url.path, '/logon-mts/mtsEntryPoint')

    def get_query_dict(self, url):
        query_str = urlsplit(url).query
        return QueryDict(query_str)

    def decode_saml_request(self, encoded_saml_request):
        return str(OneLogin_Saml2_Utils.decode_base64_and_inflate(encoded_saml_request))
