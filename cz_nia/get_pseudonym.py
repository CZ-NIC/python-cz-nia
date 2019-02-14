"""Views for communication with NIA."""
from base64 import b64decode
from enum import Enum, unique

from lxml.etree import QName
from zeep import Client, Settings
from zeep.cache import SqliteCache
from zeep.exceptions import Error
from zeep.ns import WSA, WSP
from zeep.transports import Transport
from zeep.xsd import AnyObject

from cz_nia import NIAException
from cz_nia.message import ZtotozneniMessage
from cz_nia.wsse.signature import BinarySignature, SAMLTokenSignature

SETTINGS = Settings(forbid_entities=False, strict=False)


@unique
class NIANamespaces(str, Enum):
    """Enum for NIA namespaces not included in WSDL."""

    WS_TRUST = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512'
    SUBMISSION = 'http://www.government-gateway.cz/wcf/submission'


@unique
class NIAConstants(str, Enum):
    """Enum for NIA constants."""

    ASSERTION = 'urn:oasis:names:tc:SAML:1.0:assertion'
    WS_TRUST_ISSUE = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue'
    WS_TRUST_SYM_KEY = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey'


def _get_wsa_header(client, address):
    """Get WSA header from the client."""
    applies_type = client.get_element(QName(WSP, 'AppliesTo'))
    reference_type = client.get_element(QName(WSA, 'EndpointReference'))
    reference = AnyObject(reference_type, reference_type(Address=address))
    return AnyObject(applies_type, applies_type(_value_1=reference))


def _call_ipsts(settings, transport):
    """Call IPSTS service and return the assertion."""
    client = Client(settings.IPSTS_WSDL,
                    wsse=BinarySignature(settings.CERTIFICATE, settings.KEY,
                                         settings.PASSWORD),
                    settings=SETTINGS, transport=transport)
    # Prepare token
    token_type = client.get_element(QName(NIANamespaces.WS_TRUST.value, 'TokenType'))
    token = AnyObject(token_type, token_type(NIAConstants.ASSERTION.value))
    # Prepare request
    request_type = client.get_element(QName(NIANamespaces.WS_TRUST.value, 'RequestType'))
    request = AnyObject(request_type, request_type(NIAConstants.WS_TRUST_ISSUE.value))
    # Prepare key
    key_type = client.get_element(QName(NIANamespaces.WS_TRUST.value, 'KeyType'))
    key = AnyObject(key_type, key_type(NIAConstants.WS_TRUST_SYM_KEY.value))
    # Prepare WSA header
    applies = _get_wsa_header(client, settings.FPSTS_ADDRESS)
    # Call the service
    service = client.bind('SecurityTokenService', 'WS2007HttpBinding_IWSTrust13Sync2')
    try:
        response = service.Trust13Issue(_value_1=[token, request, key, applies])
    except Error as err:
        raise NIAException(err)
    return response.RequestSecurityTokenResponse[0]['_value_1'][3]['_value_1']


def _call_fpsts(settings, transport, assertion):
    """Call FPSTS service and return the assertion."""
    client = Client(settings.FPSTS_WSDL, wsse=SAMLTokenSignature(assertion),
                    settings=SETTINGS, transport=transport)
    # prepare request
    request_type = client.get_element(QName(NIANamespaces.WS_TRUST.value, 'RequestType'))
    request = AnyObject(request_type, request_type(NIAConstants.WS_TRUST_ISSUE.value))
    # Prepare WSA header
    applies = _get_wsa_header(client, settings.PUBLIC_ADDRESS)
    # Call the service
    service = client.bind('SecurityTokenService', 'WS2007FederationHttpBinding_IWSTrust13Sync')
    try:
        response = service.Trust13Issue(_value_1=[applies, request])
    except Error as err:
        raise NIAException(err)
    return response.RequestSecurityTokenResponse[0]['_value_1'][3]['_value_1']


def _call_submission(settings, transport, assertion, message):
    """Call Submission service and return the body."""
    client = Client(settings.PUBLIC_WSDL, wsse=SAMLTokenSignature(assertion),
                    settings=SETTINGS, transport=transport)
    # Prepare the Body
    bodies_type = client.get_type(QName(NIANamespaces.SUBMISSION.value, 'ArrayOfBodyPart'))
    body_part_type = client.get_type(QName(NIANamespaces.SUBMISSION.value, 'BodyPart'))
    # Call the service
    service = client.bind('Public', 'Token')
    try:
        response = service.Submit(message.ACTION,
                                  bodies_type(body_part_type(Body={'_value_1': message.pack()})), '')
    except Error as err:
        raise NIAException(err)
    return b64decode(response.BodyBase64XML)


def get_pseudonym(settings, user_data):
    """Get pseudonym from NIA servers for given user data."""
    transport = Transport(cache=SqliteCache(path=settings.CACHE_PATH, timeout=settings.CACHE_TIMEOUT),
                          timeout=settings.TRANSPORT_TIMEOUT)
    fp_assertion = _call_ipsts(settings, transport)
    sub_assertion = _call_fpsts(settings, transport, fp_assertion)
    message = ZtotozneniMessage(user_data)
    body = _call_submission(settings, transport, sub_assertion, message)
    return message.unpack(body)
