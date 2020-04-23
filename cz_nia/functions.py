"""Views for communication with NIA."""
from base64 import b64decode
from enum import Enum, unique
from typing import Any, Dict

from lxml.etree import Element, QName, tostring
from zeep import Client, Settings
from zeep.cache import SqliteCache
from zeep.exceptions import Error
from zeep.ns import WSA, WSP
from zeep.plugins import HistoryPlugin
from zeep.transports import Transport
from zeep.xsd import AnyObject

from cz_nia.exceptions import NiaException
from cz_nia.message import (ChangeAuthenticatorMessage, IdentificationMessage, NiaMessage, NotificationMessage,
                            NotificationResult, WriteAuthenticatorMessage)
from cz_nia.settings import CzNiaAppSettings
from cz_nia.wsse.signature import BinarySignature, SAMLTokenSignature

SETTINGS = Settings(forbid_entities=False, strict=False)
ASSERTION = 'urn:oasis:names:tc:SAML:1.0:assertion'


@unique
class NiaNamespaces(str, Enum):
    """Enum for NIA namespaces not included in WSDL."""

    WS_TRUST = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512'
    SUBMISSION = 'http://www.government-gateway.cz/wcf/submission'


def _log_history(history: HistoryPlugin, settings: CzNiaAppSettings, endpoint: str, success: bool = True):
    """Print debug info from history plugin."""
    if settings.DEBUG:
        if not success:
            print('Exception in {} endpoint:'.format(endpoint))
        print('Message sent to {} endpoint:'.format(endpoint))
        print(tostring(history.last_sent['envelope'], pretty_print=True, encoding='unicode'))
        print('Message received from {} endpoint:'.format(endpoint))
        print(tostring(history.last_received['envelope'], pretty_print=True, encoding='unicode'))


def _get_wsa_header(client: Client, address: str) -> AnyObject:
    """Get WSA header from the client."""
    applies_type = client.get_element(QName(WSP, 'AppliesTo'))
    reference_type = client.get_element(QName(WSA, 'EndpointReference'))
    reference = AnyObject(reference_type, reference_type(Address=address))
    return AnyObject(applies_type, applies_type(_value_1=reference))


def _call_identity(settings: CzNiaAppSettings, transport: Transport) -> Element:
    """Call IPSTS (Identity provider) service and return the assertion."""
    plugins = []
    history = None
    if settings.DEBUG:
        history = HistoryPlugin()
        plugins.append(history)
    client = Client(settings.IDENTITY_WSDL,
                    wsse=BinarySignature(settings.CERTIFICATE, settings.KEY,
                                         settings.PASSWORD),
                    settings=SETTINGS, transport=transport, plugins=plugins)
    # Prepare token
    token_type = client.get_element(QName(NiaNamespaces.WS_TRUST.value, 'TokenType'))
    token = AnyObject(token_type, token_type(ASSERTION))
    # Prepare request
    request_type = client.get_element(QName(NiaNamespaces.WS_TRUST.value, 'RequestType'))
    request = AnyObject(request_type, request_type(NiaNamespaces.WS_TRUST.value + '/Issue'))
    # Prepare key
    key_type = client.get_element(QName(NiaNamespaces.WS_TRUST.value, 'KeyType'))
    key = AnyObject(key_type, key_type(NiaNamespaces.WS_TRUST.value + '/SymmetricKey'))
    # Prepare WSA header
    applies = _get_wsa_header(client, settings.FEDERATION_ADDRESS)
    # Call the service
    service = client.bind('SecurityTokenService', 'WS2007HttpBinding_IWSTrust13Sync2')
    try:
        response = service.Trust13Issue(_value_1=[token, request, key, applies])
    except Error as err:
        _log_history(history, settings, 'IPSTS', success=False)
        raise NiaException(err)
    _log_history(history, settings, 'IPSTS')
    return response.RequestSecurityTokenResponse[0]['_value_1'][3]['_value_1']


def _call_federation(settings: CzNiaAppSettings, transport: Transport, assertion: Element) -> Element:
    """Call FPSTS (Federation provider) service and return the assertion."""
    plugins = []
    history = None
    if settings.DEBUG:
        history = HistoryPlugin()
        plugins.append(history)
    client = Client(settings.FEDERATION_WSDL, wsse=SAMLTokenSignature(assertion),
                    settings=SETTINGS, transport=transport, plugins=plugins)
    # prepare request
    request_type = client.get_element(QName(NiaNamespaces.WS_TRUST.value, 'RequestType'))
    request = AnyObject(request_type, request_type(NiaNamespaces.WS_TRUST.value + '/Issue'))
    # Prepare WSA header
    applies = _get_wsa_header(client, settings.PUBLIC_ADDRESS)
    # Call the service
    service = client.bind('SecurityTokenService', 'WS2007FederationHttpBinding_IWSTrust13Sync')
    try:
        response = service.Trust13Issue(_value_1=[applies, request])
    except Error as err:
        _log_history(history, settings, 'FPSTS', success=False)
        raise NiaException(err)
    _log_history(history, settings, 'FPSTS')
    return response.RequestSecurityTokenResponse[0]['_value_1'][3]['_value_1']


def _call_submission(settings: CzNiaAppSettings, transport: Transport, assertion, message: NiaMessage) -> bytes:
    """Call Submission service and return the body."""
    plugins = []
    history = None
    if settings.DEBUG:
        history = HistoryPlugin()
        plugins.append(history)
    client = Client(settings.PUBLIC_WSDL, wsse=SAMLTokenSignature(assertion),
                    settings=SETTINGS, transport=transport, plugins=plugins)
    # Prepare the Body
    bodies_type = client.get_type(QName(NiaNamespaces.SUBMISSION.value, 'ArrayOfBodyPart'))
    body_part_type = client.get_type(QName(NiaNamespaces.SUBMISSION.value, 'BodyPart'))
    # Call the service
    service = client.bind('Public', 'Token')
    try:
        response = service.Submit(message.action,
                                  bodies_type(body_part_type(Body={'_value_1': message.pack()})), '')
    except Error as err:
        _log_history(history, settings, 'Submission', success=False)
        raise NiaException(err)
    _log_history(history, settings, 'Submission')
    return b64decode(response.BodyBase64XML)


def get_pseudonym(settings: CzNiaAppSettings, user_data: Dict[str, Any]) -> str:
    """Get pseudonym from NIA servers for given user data."""
    transport = Transport(cache=SqliteCache(path=settings.CACHE_PATH, timeout=settings.CACHE_TIMEOUT),
                          timeout=settings.TRANSPORT_TIMEOUT)
    fp_assertion = _call_identity(settings, transport)
    sub_assertion = _call_federation(settings, transport, fp_assertion)
    message = IdentificationMessage(user_data)
    body = _call_submission(settings, transport, sub_assertion, message)
    return message.unpack(body)


def write_authenticator(settings: CzNiaAppSettings, data):
    """Write the issued VIP."""
    transport = Transport(cache=SqliteCache(path=settings.CACHE_PATH, timeout=settings.CACHE_TIMEOUT),
                          timeout=settings.TRANSPORT_TIMEOUT)
    fp_assertion = _call_identity(settings, transport)
    sub_assertion = _call_federation(settings, transport, fp_assertion)
    # Create the request
    message = WriteAuthenticatorMessage(data)
    body = _call_submission(settings, transport, sub_assertion, message)
    return message.unpack(body)


def change_authenticator(settings: CzNiaAppSettings, data: Dict[str, str]):
    """Write a change to the VIP."""
    transport = Transport(cache=SqliteCache(path=settings.CACHE_PATH, timeout=settings.CACHE_TIMEOUT),
                          timeout=settings.TRANSPORT_TIMEOUT)
    fp_assertion = _call_identity(settings, transport)
    sub_assertion = _call_federation(settings, transport, fp_assertion)
    # Create the request
    message = ChangeAuthenticatorMessage(data)
    body = _call_submission(settings, transport, sub_assertion, message)
    return message.unpack(body)


def get_notification(settings: CzNiaAppSettings, data: Dict[str, str] = None) -> NotificationResult:
    """Get notifications."""
    transport = Transport(cache=SqliteCache(path=settings.CACHE_PATH, timeout=settings.CACHE_TIMEOUT),
                          timeout=settings.TRANSPORT_TIMEOUT)
    fp_assertion = _call_identity(settings, transport)
    sub_assertion = _call_federation(settings, transport, fp_assertion)
    # Create the request
    message = NotificationMessage(data)
    body = _call_submission(settings, transport, sub_assertion, message)
    return message.unpack(body)
