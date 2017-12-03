import logging
import re

from django import http
from django.conf import settings
from django.shortcuts import redirect, render
from django.core.exceptions import ImproperlyConfigured
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET
from django.contrib.auth import authenticate, REDIRECT_FIELD_NAME, login as auth_login
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required, user_passes_test

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.response import OneLogin_Saml2_Response
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML

from .bundles import Bundle, AuthStrength
from . import app_settings

log = logging.getLogger(__name__)


def get_saml2_settings(auth_strength=AuthStrength.low):
    bundle_settings = Bundle().get_settings(authn_context=auth_strength.authn_context)
    return OneLogin_Saml2_Settings(settings=bundle_settings, sp_validation_only=True)


def prepare_django_request(request):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    return {
        'https': 'on' if request.is_secure() else 'off',
        'http_host': request.META['HTTP_HOST'],
        'script_name': request.META['PATH_INFO'],
        'server_port': request.META.get('HTTP_X_FORWARDED_PORT') or request.META.get('SERVER_PORT'),
        'get_data': request.GET.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        'post_data': request.POST.copy()
    }


def init_saml2_auth(request, strength=AuthStrength.low):
    req = prepare_django_request(request)
    return OneLogin_Saml2_Auth(req, get_saml2_settings(strength))


@require_GET
def login(request):
    """
    Log in using the configured RealMe service.
    Configured with the BUNDLE_NAME setting.
    'FAKE' value uses a realme-themed standard Django login.
    Any other uses the matching bundle defined in the BUNDLES setting
    """
    bundle_name = getattr(settings, 'BUNDLE_NAME', 'FAKE')

    if bundle_name == 'FAKE':
        return fake_realme_login(request)
    elif bundle_name not in settings.BUNDLES:
        raise ImproperlyConfigured(
            "No bundle named '{}' defined in settings.BUNDLES".format(bundle_name)
        )

    # the url to return to after login. Default to root url
    target_url = request.GET.get(REDIRECT_FIELD_NAME, '/')

    if 'strength' in request.GET:
        strength_param = request.GET.get('strength').lower()

        # if a valid strength is requested then use that
        try:
            auth_strength = AuthStrength[strength_param]
        except KeyError:
            log.warn("unrecognised realme auth strength '%s'. Defaulting to 'low'", strength_param)
            auth_strength = AuthStrength.low

    else:
        auth_strength = AuthStrength.low

    auth = init_saml2_auth(request, auth_strength)
    url = auth.login(return_to=target_url)

    log.debug('sp login SAMLRequest = %s', auth.get_last_request_xml())
    log.debug('sp login url: %s', url)

    return redirect(url)


def fake_realme_login(request):
    """
    A standard Django login with a realme-themed template.
    """
    return auth_views.login(request, template_name='realme/fake-login.html')


@user_passes_test(lambda user: user.is_superuser)
def metadata(request):
    return http.HttpResponse(Bundle().render_metadata(), content_type='text/plain')


def get_status(dom):
    """
    Gets Status from a Response, including RealMe inner subcode, if present.

    This provides a replacement for OneLogin_Saml2_Utils.get_status(), which only
    returns a subcode if there is no StatusMessage. RealMe errors return both a
    subcode and a sub-code.

    :param dom: The Response as XML
    :type: Document

    :returns: The Status, an array with code, subcode and a message.
    :rtype: dict
    """
    status = {}

    status_entry = OneLogin_Saml2_XML.query(dom, '/samlp:Response/samlp:Status')
    if len(status_entry) != 1:
        raise Exception('Missing valid Status on response')

    code_entry = OneLogin_Saml2_XML.query(dom, '/samlp:Response/samlp:Status/samlp:StatusCode', status_entry[0])
    if len(code_entry) != 1:
        raise Exception('Missing valid Status Code on response')
    code = code_entry[0].values()[0]
    status['code'] = code

    subcode_entry = OneLogin_Saml2_XML.query(dom, '/samlp:Response/samlp:Status/samlp:StatusCode/samlp:StatusCode', status_entry[0])
    if len(subcode_entry) == 1:
        status['subcode'] = subcode_entry[0].values()[0]

    status['msg'] = ''
    message_entry = OneLogin_Saml2_XML.query(dom, '/samlp:Response/samlp:Status/samlp:StatusMessage', status_entry[0])
    if len(message_entry) == 1:
        status['msg'] = message_entry[0].text

    return status


def get_authentication_strength(dom):
    """
    Gets authentication strength from a Response
    :param dom: The Response as XML, with the Assertion decrypted
    :type: Document
    :returns: the authentication strength
    :rtype: AuthStrength
    """
    authn_context_entry = OneLogin_Saml2_XML.query(
        dom, '/samlp:Response/saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef')

    if len(authn_context_entry) != 1:
        raise Exception('Missing authentication context on response')

    authn_context = authn_context_entry[0].text

    log.debug("found AuthnContextClassRef: %s", authn_context)

    return AuthStrength.from_authn_context(authn_context)



@csrf_exempt
def assertion_consumer_service(request):

    if request.method != 'POST':
        return http.HttpResponseBadRequest()

    target_url = request.POST.get('RelayState', '/')
    response = http.HttpResponseRedirect(target_url)

    auth = init_saml2_auth(request)
    saml2_response = OneLogin_Saml2_Response(
        get_saml2_settings(),
        request.POST['SAMLResponse'],
    )

    if saml2_response.encrypted:
        response_document = saml2_response.decrypted_document
    else:
        response_document = saml2_response.document

    log.debug(
        'decoded and decrypted SAMLResponse = %s',
        OneLogin_Saml2_XML.to_string(response_document).decode('utf-8')
    )

    status = get_status(response_document)
    # status example: {code: FOO, msg: BAR}
    code = status.get('code')
    if code != OneLogin_Saml2_Constants.STATUS_SUCCESS:
        log.error('saml response status: {}'.format(status))
        subcode = status.get('subcode', '')
        realme_inner_code = subcode.split(':')[-1]
        assert realme_inner_code
        response.set_cookie(
            app_settings.EXCHANGE_COOKIE_NAME,
            realme_inner_code,
            secure=settings.SESSION_COOKIE_SECURE
        )
        return response

    auth.process_response()
    if auth.is_authenticated():
        user = authenticate(saml2_auth=auth)
        if user and user.is_active:
            auth_login(request, user)
            auth_strength = get_authentication_strength(response_document)
            request.session['realme_strength'] = auth_strength.name
            return response

    response.set_cookie(
        app_settings.EXCHANGE_COOKIE_NAME,
        'RealMeError',
        secure=settings.SESSION_COOKIE_SECURE
    )
    return response


def extract_opaque_token(xml):
    """
    Extract raw opaque token from response xml.

    Warning: Must keep the token as it is. Do not use this way:

        from lxml import etree
        elem = etree.fromstring(xml).xpath('//saml2:Assertion', namespaces=NAMESPACES)[0]
        return etree.tostring(elem)

    xpath will add used namespaces to elem, so the token is changed.
    """
    match = re.search(r'<wst:RequestedSecurityToken>(.+?)</wst:RequestedSecurityToken>', xml)
    return match.group(1).strip() if match else ''


def escape_opaque_token(xml):
    """
    Escape raw token xml to put it in form field.

    The RealMe Java backend use this function to escape:

        org.apache.commons.lang.StringEscapeUtils.escapeHtml

    which will escape quote, while most Python libraries don't do this by default.
    So the `quote=True` arg is important.
    """
    from html import escape
    return escape(xml, quote=True)


@login_required
def seamless(request, target_sp=''):
    bundle = Bundle()
    r = bundle.send_opaque_token_request(request.user, target_sp)
    xml = r.content.decode(r.encoding)
    log.debug('opaque token response: %s', xml)
    opaque_token_raw = extract_opaque_token(xml)
    assert opaque_token_raw in xml
    log.debug('opaque token raw: %s', opaque_token_raw)
    opaque_token_escaped = escape_opaque_token(opaque_token_raw)
    log.debug('opaque token escaped: %s', opaque_token_escaped)
    response = render(request, 'realme/seamless.html', context={
        'relay_state': bundle.config.get('target_sps', {}).get(target_sp, {}).get('relay_state', ''),
        'opaque_token': opaque_token_escaped,
        'seamless_logon_service': bundle.config['seamless_logon_service'],
    })
    content = response.content.decode('utf-8')
    assert opaque_token_escaped in content
    log.debug('seamless logon request: %s', content)
    return response
