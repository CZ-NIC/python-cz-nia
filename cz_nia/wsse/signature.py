"""WSSE signature objects."""
import xmlsec
from lxml.etree import Element, QName, SubElement
from zeep import ns
from zeep.utils import detect_soap_env
from zeep.wsse.signature import Signature, _make_sign_key, _sign_node
from zeep.wsse.utils import ensure_id, get_security_header


def _signature_prepare(envelope, key):
    """Prepare all the data for signature.

    Mostly copied from zeep.wsse.signature.
    """
    soap_env = detect_soap_env(envelope)
    # Create the Signature node.
    signature = xmlsec.template.create(envelope, xmlsec.Transform.EXCL_C14N, xmlsec.Transform.RSA_SHA1)

    # Add a KeyInfo node with X509Data child to the Signature. XMLSec will fill
    # in this template with the actual certificate details when it signs.
    key_info = xmlsec.template.ensure_key_info(signature)
    x509_data = xmlsec.template.add_x509_data(key_info)
    xmlsec.template.x509_data_add_issuer_serial(x509_data)
    xmlsec.template.x509_data_add_certificate(x509_data)

    # Insert the Signature node in the wsse:Security header.
    security = get_security_header(envelope)
    security.insert(0, signature)
    security.append(Element(QName(ns.WSU, 'Timestamp')))

    # Perform the actual signing.
    ctx = xmlsec.SignatureContext()
    ctx.key = key
    _sign_node(ctx, signature, envelope.find(QName(soap_env, 'Body')))
    _sign_node(ctx, signature, security.find(QName(ns.WSU, 'Timestamp')))
    ctx.sign(signature)

    # Place the X509 data inside a WSSE SecurityTokenReference within
    # KeyInfo. The recipient expects this structure, but we can't rearrange
    # like this until after signing, because otherwise xmlsec won't populate
    # the X509 data (because it doesn't understand WSSE).
    sec_token_ref = SubElement(key_info, QName(ns.WSSE, 'SecurityTokenReference'))
    return security, sec_token_ref, x509_data


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


class BinarySignature(Signature):
    """Sign given SOAP envelope with WSSE sif using given key file and cert file.

    Place the ky information into BinarySecurityElement.
    """

    def apply(self, envelope, headers):
        """Plugin entry point."""
        key = _make_sign_key(self.key_data, self.cert_data, self.password)
        _sign_envelope_with_key_binary(envelope, key)
        return envelope, headers
