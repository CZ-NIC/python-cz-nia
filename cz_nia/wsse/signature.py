"""WSSE signature objects."""
import datetime
from base64 import b64decode

import xmlsec
from lxml.etree import Element, ETXPath, QName, SubElement
from zeep import ns
from zeep.utils import detect_soap_env
from zeep.wsse.signature import (MemorySignature as ZeepMemorySignature, Signature as ZeepSignature, _make_sign_key,
                                 _sign_node, _verify_envelope_with_key)
from zeep.wsse.utils import ensure_id, get_security_header, get_timestamp


def _signature_prepare(envelope, key, sign_method=xmlsec.Transform.RSA_SHA1):
    """Prepare all the data for signature.

    Mostly copied from zeep.wsse.signature.
    """
    soap_env = detect_soap_env(envelope)
    # Create the Signature node.
    signature = xmlsec.template.create(envelope, xmlsec.Transform.EXCL_C14N, sign_method)

    # Add a KeyInfo node with X509Data child to the Signature. XMLSec will fill
    # in this template with the actual certificate details when it signs.
    key_info = xmlsec.template.ensure_key_info(signature)
    x509_data = xmlsec.template.add_x509_data(key_info)
    xmlsec.template.x509_data_add_issuer_serial(x509_data)
    xmlsec.template.x509_data_add_certificate(x509_data)

    # Insert the Signature node in the wsse:Security header.
    security = get_security_header(envelope)
    security.insert(0, signature)

    # Prepare Timestamp
    timestamp = Element(QName(ns.WSU, 'Timestamp'))
    created = Element(QName(ns.WSU, 'Created'))
    created.text = get_timestamp()
    expires = Element(QName(ns.WSU, 'Expires'))
    expires.text = get_timestamp(datetime.datetime.utcnow() + datetime.timedelta(minutes=5))
    timestamp.append(created)
    timestamp.append(expires)
    security.insert(0, timestamp)

    # Perform the actual signing.
    ctx = xmlsec.SignatureContext()
    ctx.key = key
    _sign_node(ctx, signature, envelope.find(QName(soap_env, 'Body')))
    _sign_node(ctx, signature, security.find(QName(ns.WSU, 'Timestamp')))

    # Remove newlines from signature...
    for element in signature.iter():
        if element.text is not None and '\n' in element.text:
            element.text = element.text.replace('\n', '')
        if element.tail is not None and '\n' in element.tail:
            element.tail = element.tail.replace('\n', '')

    ctx.sign(signature)

    # Place the X509 data inside a WSSE SecurityTokenReference within
    # KeyInfo. The recipient expects this structure, but we can't rearrange
    # like this until after signing, because otherwise xmlsec won't populate
    # the X509 data (because it doesn't understand WSSE).
    sec_token_ref = SubElement(key_info, QName(ns.WSSE, 'SecurityTokenReference'))
    return security, sec_token_ref, x509_data


def _sign_envelope_with_key(envelope, key):
    """Overriden to use the `_signature_prepare`."""
    security, sec_token_ref, x509_data = _signature_prepare(envelope, key)
    sec_token_ref.append(x509_data)


def _sign_envelope_with_key_binary(envelope, key):
    """Perofrm signature and place the key info in to BinarySecurityToken."""
    security, sec_token_ref, x509_data = _signature_prepare(envelope, key)
    ref = SubElement(
        sec_token_ref, QName(ns.WSSE, 'Reference'),
        {'ValueType': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3'})
    ref_id = ensure_id(ref)
    bintok = Element(
        QName(ns.WSSE, 'BinarySecurityToken'),
        {QName(ns.WSU, 'Id'): ref_id,
         'ValueType': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3',
         'EncodingType': 'http://docs.oasis-open.org/wss/2004/01/'
                         'oasis-200401-wss-soap-message-security-1.0#Base64Binary'})
    bintok.text = x509_data.find(QName(ns.DS, 'X509Certificate')).text
    security.insert(1, bintok)
    x509_data.getparent().remove(x509_data)


def _sign_envelope_with_saml(envelope, key, assertion, assertion_id):
    """Perform singature and place the key info into SecurityTokenReference."""
    security, sec_token_ref, x509_data = _signature_prepare(envelope, key, sign_method=xmlsec.Transform.HMAC_SHA1)
    # Update the sec_tok_ref object
    sec_token_ref.attrib['TokenType'] = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1'
    key_iden_ref = SubElement(
        sec_token_ref, QName(ns.WSSE, 'KeyIdentifier'),
        {'ValueType': 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID'})
    key_iden_ref.text = assertion_id
    security.insert(1, assertion)
    x509_data.getparent().remove(x509_data)


class MemorySignature(ZeepMemorySignature):
    """Overriden to use the changed `_sing_envelope_with_key`."""

    def apply(self, envelope, headers):
        """Plugin entry point."""
        key = _make_sign_key(self.key_data, self.cert_data, self.password)
        _sign_envelope_with_key(envelope, key)
        return envelope, headers


class Signature(ZeepSignature):
    """Overriden to use the changed `_sing_envelope_with_key`."""

    def apply(self, envelope, headers):
        """Plugin entry point."""
        key = _make_sign_key(self.key_data, self.cert_data, self.password)
        _sign_envelope_with_key(envelope, key)
        return envelope, headers


class BinarySignature(ZeepSignature):
    """Sign given SOAP envelope with WSSE sif using given key file and cert file.

    Place the ky information into BinarySecurityElement.
    """

    def apply(self, envelope, headers):
        """Plugin entry point."""
        key = _make_sign_key(self.key_data, self.cert_data, self.password)
        _sign_envelope_with_key_binary(envelope, key)
        return envelope, headers


class SAMLTokenSignature(object):
    """Sign given SOAP envelope with WSSE sig using given HMAC key."""

    def __init__(self, assertion):
        """Parse necessary data from the assertion."""
        # XXX: For now we assume that the Assertion is lxml tree
        # XXX: This can change later...
        find = ETXPath("//{}/text()".format(QName('http://docs.oasis-open.org/ws-sx/ws-trust/200512', 'BinarySecret')))
        self.assertion = assertion
        self.key_data = b64decode(find(assertion)[0])
        self.assertion_id = assertion.get('AssertionID')

    def apply(self, envelope, headers, signatures=None):
        """Plugin entry point."""
        key = xmlsec.Key.from_binary_data(xmlsec.KeyData.HMAC, self.key_data)
        _sign_envelope_with_saml(envelope, key, self.assertion, self.assertion_id)
        return envelope, headers

    def verify(self, envelope):
        """Plugin exit point."""
        key = xmlsec.Key.from_binary_data(xmlsec.KeyData.HMAC, self.key_data)
        _verify_envelope_with_key(envelope, key)
        return envelope
