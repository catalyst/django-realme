import uuid
import xmlsec
import requests
from lxml import etree
from path import Path
from enum import Enum
from datetime import datetime, timedelta

from django.conf import settings
from django.core.urlresolvers import reverse
from django.template.loader import render_to_string

from onelogin.saml2.constants import OneLogin_Saml2_Constants as constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from . import app_settings

import logging
log = logging.getLogger(__name__)

URL_TOKEN_ISSUE = 'https://ws.ite.realme.govt.nz/iCMS/Issue_v1_1'

NAMESPACES = {
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
    'ec': "http://www.w3.org/2001/10/xml-exc-c14n#",
    'env': 'http://www.w3.org/2003/05/soap-envelope',
    'soap': 'http://www.w3.org/2003/05/soap-envelope',
    'wsa': "http://www.w3.org/2005/08/addressing",
    'wsp': 'http://schemas.xmlsoap.org/ws/2004/09/policy',
    'wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
    'wsse11': 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0',
    'wst': "http://docs.oasis-open.org/ws-sx/ws-trust/200512",
    'wst14': "http://docs.oasis-open.org/ws-sx/ws-trust/200802",
    'wsu': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
    'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion',
    'iCMS': "urn:nzl:govt:ict:stds:authn:deployment:igovt:gls:iCMS:1_0",
}

# override the TODOs with `BUNDLES` in your settings.py
BUNDLES_DEFAULT = {
    'MTS': {
        'idp_entity_id': 'https://mts.realme.govt.nz/saml2',
        'saml_idp_cer': 'mts_login_saml_idp.cer',
        'mutual_ssl_idp_cer': 'mts_mutual_ssl_idp.cer',
        'single_sign_on_service': 'https://mts.realme.govt.nz/logon-mts/mtsEntryPoint',
        'seamless_logon_service': 'NA',
        'saml_sp_cer': 'mts_saml_sp.cer',
        'saml_sp_key': 'mts_saml_sp.key',
        'mutual_ssl_sp_cer': 'mts_mutual_ssl_sp.cer',
        'mutual_ssl_sp_key': 'mts_mutual_ssl_sp.key',
        'sp_entity_id': '',  # TODO
        'site_url': '',  # TODO
    },
    'ITE': {
        'idp_entity_id': 'https://www.ite.logon.realme.govt.nz/saml2',
        'saml_idp_cer': 'ite.signing.logon.realme.govt.nz.cer',
        'mutual_ssl_idp_cer': 'ws.ite.realme.govt.nz.cer',
        'single_sign_on_service': 'https://www.ite.logon.realme.govt.nz/sso/logon/metaAlias/logon/logonidp',
        'seamless_logon_service': 'https://www.ite.logon.realme.govt.nz/cls/seamlessEndpoint',
        'saml_sp_cer': '',  # TODO
        'saml_sp_key': '',  # TODO
        'mutual_ssl_sp_cer': '',  # TODO
        'mutual_ssl_sp_key': '',  # TODO
        'sp_entity_id': '',  # TODO
        'site_url': '',  # TODO
    },
    'PRD': {
        'idp_entity_id': 'https://www.logon.realme.govt.nz/saml2',
        'saml_idp_cer': 'signing.logon.realme.govt.nz.cer',
        'mutual_ssl_idp_cer': 'ws.realme.govt.nz.cer',
        'single_sign_on_service': 'https://www.logon.realme.govt.nz/sso/logon/metaAlias/logon/logonidp',
        'seamless_logon_service': 'https://www.logon.realme.govt.nz/cls/seamlessEndpoint',
        'saml_sp_cer': '',  # TODO
        'saml_sp_key': '',  # TODO
        'mutual_ssl_sp_cer': '',  # TODO
        'mutual_ssl_sp_key': '',  # TODO
        'sp_entity_id': '',  # TODO
        'site_url': '',  # TODO
    }
}


def dt_fmt(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def pretty_xml(xml):
    element = etree.fromstring(xml)
    return etree.tostring(element, pretty_print=True).decode('utf-8')


def get_file_body(text):
    lines = text.strip().splitlines()
    start = 1 if lines[0].startswith('-----BEGIN ') else 0
    end = -1 if lines[-1].startswith('-----END ') else None
    return ''.join(lines[start:end])


class AuthnContextClassRef(object):
    LowStrength = 'urn:nzl:govt:ict:stds:authn:deployment:GLS:SAML:2.0:ac:classes:LowStrength'
    ModStrength = 'urn:nzl:govt:ict:stds:authn:deployment:GLS:SAML:2.0:ac:classes:ModStrength'
    # SHOULD NOT be used by a integrating Client SP without first obtaining approval from the RealMe Logon Service.
    ModStrength__OTP_Token_SID = 'urn:nzl:govt:ict:stds:authn:deployment:GLS:SAML:2.0:ac:classes:ModStrength::OTP:Token:SID'
    ModStrength__OTP_Mobile_SMS = 'urn:nzl:govt:ict:stds:authn:deployment:GLS:SAML:2.0:ac:classes:ModStrength::OTP:Mobile:SMS'


class AuthStrength(Enum):
    """
    Enumeration of supported RealMe authentication strengths
    """

    low = (10, AuthnContextClassRef.LowStrength)
    moderate = (20, AuthnContextClassRef.ModStrength)

    def __init__(self, rating, authn_context):
        """
        :param rating: The 'Responder Deemed Authentication Strength', given in RealMe specs
        :param authn_context: the default AuthnContextClassRef to use in RealMe authentication
        """
        self.rating = rating
        self.authn_context = authn_context

    @classmethod
    def from_authn_context(cls, authn_context):
        for auth_strength in cls:
            if authn_context == auth_strength.authn_context:
                return auth_strength
        raise ValueError("Unrecognised AuthnContextClassRef '{}'".format(authn_context))


class Bundle(object):

    def __init__(self, site_url=None, bundles_root=None, name=None, healthcheck=True):
        self.name = name or app_settings.BUNDLE_NAME
        self.bundles_final_config = self.get_bundles_final_config()
        self.config = self.bundles_final_config[self.name]

        self.bundles_root = Path(bundles_root or app_settings.BUNDLES_ROOT)
        self.path = self.bundles_root / self.name

        self.site_url = site_url or self.config.get('site_url') or settings.SITE_URL
        if healthcheck:
            self.healthcheck()

    def healthcheck(self):
        assert self.name in self.bundles_final_config, 'invalid bundle name: {}'.format(self.name)
        assert self.bundles_root.isdir(), self.bundles_root
        assert self.path.isdir(), self.path

        fields = (
            'saml_idp_cer',
            'mutual_ssl_idp_cer',
            'saml_sp_cer',
            'saml_sp_key',
            'mutual_ssl_sp_cer',
            'mutual_ssl_sp_key',
        )

        for field in fields:
            if self.config.get(field):
                assert self.file_path(field).isfile()

        for prefix in ('saml_sp', 'mutual_ssl_sp'):
            self.check_cer_and_key(prefix)


    def __str__(self):
        return self.name

    def get_bundles_final_config(self):
        """
        Load `BUNDLES` from settings.py, and merge with `BUNDLES_DEFAULT`.

        The key in `BUNDLES` can have sub name.
        E.g.: You can define 2 ITE environments, ITE-uat and ITE-testing
        """
        final_config = {}
        for key, conf in app_settings.BUNDLES.items():
            env = key.split('-')[0]  # ITE-uat --> ITE
            default_conf = BUNDLES_DEFAULT[env].copy()
            default_conf.update(conf)  # update default with conf
            final_config[key] = default_conf
        return final_config

    def get_target_sp_entity_id(self, target_sp):
        return self.config.get('target_sps', {}).get(target_sp, {}).get('entity_id', '')

    def check_cer_and_key(self, prefix):
        from subprocess import check_output
        cer_field = '{}_cer'.format(prefix)
        key_field = '{}_key'.format(prefix)
        if self.config.get(cer_field) and self.config.get(key_field):
            cer_path = self.file_path(cer_field)
            key_path = self.file_path(key_field)
            cmd = 'openssl x509 -noout -modulus -in {}'.format(cer_path)
            s1 = check_output(cmd.split())
            cmd = 'openssl rsa -noout -modulus -in {}'.format(key_path)
            s2 = check_output(cmd.split())
            assert s1 == s2

    def file_path(self, field):
        return self.path / self.config[field]

    def file_text(self, field):
        return self.file_path(field).text().strip()

    def file_body(self, field):
        return get_file_body(self.file_text(field))

    @property
    def idp_cer_body(self):
        return self.file_body('saml_idp_cer')

    @property
    def sp_cer_body(self):
        return self.file_body('saml_sp_cer')

    @property
    def sp_key_body(self):
        return self.file_body('saml_sp_key')

    def full_url(self, url):
        return self.site_url.strip('/') + url

    @property
    def idp_entity_id(self):
        return self.config['idp_entity_id']

    @property
    def sp_entity_id(self):
        return self.config['sp_entity_id'].strip()

    @property
    def sp_acs_url(self):
        return self.full_url(reverse('realme:acs'))

    def get_settings(self, authn_context=AuthnContextClassRef.LowStrength):
        return {
            "strict": True,
            "debug": settings.DEBUG,
            "security": {
                "nameIdEncrypted": False,
                "authnRequestsSigned": True,
                "requestedAuthnContext": [authn_context],
                "logoutRequestSigned": False,
                "logoutResponseSigned": False,
                "signMetadata": False,
                "wantMessagesSigned": False,
                "wantAssertionsSigned": True,
                "wantAttributeStatement": False,
                "wantNameId": True,
                "wantNameIdEncrypted": False,
                "wantAssertionsEncrypted": False,
                "signatureAlgorithm": constants.RSA_SHA1,
            },
            "sp": {
                "entityId": self.sp_entity_id,
                "assertionConsumerService": {
                    "url": self.sp_acs_url,
                    "binding": constants.BINDING_HTTP_POST,
                },
                # "singleLogoutService": {
                #     "url": "",
                #     "binding": constants.BINDING_HTTP_REDIRECT,
                # },
                "NameIDFormat": constants.NAMEID_UNSPECIFIED,
                "x509cert": self.sp_cer_body,
                "privateKey": self.sp_key_body,
            },
            "idp": {
                "entityId": self.idp_entity_id,
                "singleSignOnService": {
                    "url": self.config['single_sign_on_service'],
                    "binding": constants.BINDING_HTTP_REDIRECT,
                },
                # "singleLogoutService": {
                #     "url": "",
                #     "binding": constants.BINDING_HTTP_REDIRECT,
                # },
                "x509cert": self.idp_cer_body,
            }
        }

    def render_metadata(self):
        return render_to_string(
            'realme/metadata.xml',
            {
                'conf': self,
                'METADATA_ORG_NAME': app_settings.METADATA_ORG_NAME,
                'METADATA_ORG_DISPLAY_NAME': app_settings.METADATA_ORG_DISPLAY_NAME,
                'METADATA_ORG_URL': app_settings.METADATA_ORG_URL,
            }
        )

    @property
    def key_identifier(self):
        fp_ascii = OneLogin_Saml2_Utils.calculate_x509_fingerprint(self.sp_cer_body)
        # --> unicode str in ascii: 'b5a10daa4250aea3b036b4a2a6e66829f852363f'
        from binascii import a2b_hex, b2a_base64
        fp_hex = a2b_hex(fp_ascii)
        # --> unicode str in hex: '\xb5\xa1\r\xaaBP\xae\xa3\xb06\xb4\xa2\xa6\xe6h)\xf8R6?'
        return b2a_base64(fp_hex).strip()  # 'taENqkJQrqOwNrSipuZoKfhSNj8=\n'

    def render_opaque_token_request(self, logon_attributes_token='', target_sp_entity_id=''):
        created = datetime.utcnow()  # must use utc time
        expires = created + timedelta(minutes=5)
        return render_to_string(
            'realme/opaque_token_request_tmpl.xml',
            context={
                'conf': self,
                'created': dt_fmt(created),
                'expires': dt_fmt(expires),
                'message_id': str(uuid.uuid4()),
                'to': URL_TOKEN_ISSUE,
                'REF_IDS': ("Id-Action", "Id-MessageID", "Id-To", "Id-ReplyTo", "Id-Body", "Id-Timestamp"),
                'NAMESPACES': NAMESPACES,
                'key_identifier': self.key_identifier,
                'logon_attributes_token': logon_attributes_token,
                'target_sp_entity_id': target_sp_entity_id,
            }
        )

    def sign_opaque_token_request(self, rendered_xml):
        root_element = etree.fromstring(rendered_xml)
        xmlsec.tree.add_ids(root_element, ["Id"])  # important!
        # refer to xml/opaque_token_request_unsigned.xml for example
        signature_element = root_element.xpath('/soap:Envelope/soap:Header/wsse:Security/ds:Signature', namespaces=NAMESPACES)[0]

        key_path = self.file_path('saml_sp_key')
        assert key_path.isfile
        cer_path = self.file_path('saml_sp_cer')
        assert cer_path.isfile

        # Load private key (assuming that there is no password).
        key = xmlsec.Key.from_file(key_path, xmlsec.KeyFormat.PEM)
        assert key is not None

        # Load the certificate and add it to the key.
        key.load_cert_from_file(cer_path, xmlsec.KeyFormat.PEM)

        # Create a digital signature context (no key manager is needed).
        ctx = xmlsec.SignatureContext()
        ctx.key = key
        # Sign the template.
        ctx.sign(signature_element)
        # return a utf-8 encoded byte str
        # refer to xml/opaque_token_request_signed.xml for example
        return etree.tostring(root_element, pretty_print=True).decode('utf-8')

    def verify_opaque_token_response(self, signed_xml):
        root_element = etree.fromstring(signed_xml)
        xmlsec.tree.add_ids(root_element, ["Id"])  # important!
        signature_element = root_element.xpath('/soap:Envelope/soap:Header/wsse:Security/ds:Signature', namespaces=NAMESPACES)[0]

        cer_path = self.file_path('saml_idp_cer')
        assert cer_path.isfile
        key = xmlsec.Key.from_file(cer_path, xmlsec.KeyFormat.CERT_PEM)
        assert key is not None

        # Create a digital signature context (no key manager is needed).
        ctx = xmlsec.SignatureContext()
        ctx.key = key

        from xmlsec.error import VerificationError
        try:
            # no return value, raise exception if failed
            ctx.verify(signature_element)
        except VerificationError as e:
            log.error('verify_opaque_token_response failed: {}'.format(e))
            return False
        return True

    def send_opaque_token_request(self, user, target_sp):
        logon_attributes_token = user.profile.logon_attributes_token
        target_sp_entity_id = self.get_target_sp_entity_id(target_sp)
        rendered_xml = self.render_opaque_token_request(
            logon_attributes_token=logon_attributes_token,
            target_sp_entity_id=target_sp_entity_id,
        )
        log.debug('opaque token request unsigned: %s', rendered_xml)

        signed_xml = self.sign_opaque_token_request(rendered_xml)
        log.debug('opaque token request: %s', signed_xml)

        headers = {'content-type': 'text/xml'}
        cert = (
            self.file_path('mutual_ssl_sp_cer'),
            self.file_path('mutual_ssl_sp_key'),
        )
        return requests.post(URL_TOKEN_ISSUE, data=signed_xml, headers=headers, cert=cert)

