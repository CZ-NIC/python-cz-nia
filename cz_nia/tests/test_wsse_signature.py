"""Unittests for wsse.signature module."""
import os
from unittest import TestCase

from lxml.etree import QName
from zeep import ns
from zeep.exceptions import SignatureVerificationFailed
from zeep.wsdl.utils import get_or_create_header
from zeep.wsse.signature import OMITTED_HEADERS, _make_sign_key

from cz_nia.tests.utils import load_xml
from cz_nia.wsse import BinarySignature, MemorySignature, SAMLTokenSignature, Signature
from cz_nia.wsse.signature import _signature_prepare

CERT_FILE = os.path.join(os.path.dirname(__file__), 'certificate.pem')
KEY_FILE = os.path.join(os.path.dirname(__file__), 'key.pem')
ENVELOPE = """
    <soapenv:Envelope xmlns:tns="http://tests.python-zeep.org/" xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
    xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/">
        <soapenv:Header></soapenv:Header>
        <soapenv:Body>
            <tns:Function>
                <tns:Argument>OK</tns:Argument>
            </tns:Function>
        </soapenv:Body>
    </soapenv:Envelope>
    """
HEADER_ENVELOPE = """
    <soapenv:Envelope xmlns:tns="http://tests.python-zeep.org/" xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
    xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/">
        <soapenv:Header>
            <tns:Item></tns:Item>
        </soapenv:Header>
        <soapenv:Body>
            <tns:Function>
                <tns:Argument>OK</tns:Argument>
            </tns:Function>
        </soapenv:Body>
    </soapenv:Envelope>
    """


class TestSignaturePrepare(TestCase):
    """Unittests for _signature_prepare."""

    def setUp(self):
        with open(KEY_FILE) as key, open(CERT_FILE) as cert:
            self.key = _make_sign_key(key.read(), cert.read(), None)

    def test_newline_strip(self):
        security, _, _ = _signature_prepare(load_xml(ENVELOPE), self.key, None, None)
        signature = security.find(QName(ns.DS, 'Signature'))
        for element in signature.iter():
            if element.tag in ('{http://www.w3.org/2000/09/xmldsig#}SignatureValue',
                               '{http://www.w3.org/2000/09/xmldsig#}X509IssuerSerial',
                               '{http://www.w3.org/2000/09/xmldsig#}X509IssuerName',
                               '{http://www.w3.org/2000/09/xmldsig#}X509SerialNumber',
                               '{http://www.w3.org/2000/09/xmldsig#}X509Certificate'):
                # These are placed after the stripping, so we do not check them
                continue
            if element.text is not None:
                self.assertNotIn('\n', element.text)
            if element.tail is not None:
                self.assertNotIn('\n', element.tail)

    def test_sign_everything(self):
        envelope = load_xml(HEADER_ENVELOPE)
        security, _, _ = _signature_prepare(envelope, self.key, None, None,
                                            signatures={'body': False, 'everything': True, 'header': []})
        signature = security.find(QName(ns.DS, 'Signature'))
        # Get all references
        refs = signature.xpath('ds:SignedInfo/ds:Reference/@URI', namespaces={'ds': ns.DS})
        ID = QName(ns.WSU, 'Id')
        # All header items should be signed
        for element in get_or_create_header(envelope):
            if element.nsmap.get(element.prefix) not in OMITTED_HEADERS:
                self.assertIn('#' + element.attrib[ID], refs)
        # Body is signed
        self.assertIn('#' + envelope.find(QName(ns.SOAP_ENV_11, 'Body')).attrib[ID], refs)
        self.assertIn('#' + security.find(QName(ns.WSU, 'Timestamp')).attrib[ID], refs)

    def test_sign_body(self):
        envelope = load_xml(ENVELOPE)
        security, _, _ = _signature_prepare(envelope, self.key, None, None,
                                            signatures={'body': False, 'everything': True, 'header': []})
        signature = security.find(QName(ns.DS, 'Signature'))
        # Get all references
        refs = signature.xpath('ds:SignedInfo/ds:Reference/@URI', namespaces={'ds': ns.DS})
        ID = QName(ns.WSU, 'Id')
        # Body is signed
        self.assertIn('#' + envelope.find(QName(ns.SOAP_ENV_11, 'Body')).attrib[ID], refs)
        self.assertIn('#' + security.find(QName(ns.WSU, 'Timestamp')).attrib[ID], refs)

    def test_sign_empty(self):
        envelope = load_xml(ENVELOPE)
        security, _, _ = _signature_prepare(envelope, self.key, None, None,
                                            signatures={'body': False, 'everything': False, 'header': []})
        signature = security.find(QName(ns.DS, 'Signature'))
        # Get all references
        refs = signature.xpath('ds:SignedInfo/ds:Reference/@URI', namespaces={'ds': ns.DS})
        ID = QName(ns.WSU, 'Id')
        self.assertIn('#' + security.find(QName(ns.WSU, 'Timestamp')).attrib[ID], refs)

    def test_sign_header_item(self):
        envelope = load_xml(HEADER_ENVELOPE)
        sig_header = [{'Namespace': 'http://tests.python-zeep.org/', 'Name': 'Item'}]
        security, _, _ = _signature_prepare(envelope, self.key, None, None,
                                            signatures={'body': False, 'everything': False, 'header': sig_header})
        signature = security.find(QName(ns.DS, 'Signature'))
        # Get all references
        refs = signature.xpath('ds:SignedInfo/ds:Reference/@URI', namespaces={'ds': ns.DS})
        ID = QName(ns.WSU, 'Id')
        self.assertIn('#' + security.find(QName(ns.WSU, 'Timestamp')).attrib[ID], refs)
        header = get_or_create_header(envelope)
        self.assertIn('#' + header.find(QName('http://tests.python-zeep.org/', 'Item')).attrib[ID], refs)


class TestBinarySignature(TestCase):
    """Unittests for BinarySignature."""

    def test_signature_binary(self):
        plugin = BinarySignature(KEY_FILE, CERT_FILE)
        envelope, headers = plugin.apply(load_xml(ENVELOPE), {})
        plugin.verify(envelope)
        # Test that the reference is correct
        bintok = envelope.xpath('soapenv:Header/wsse:Security/wsse:BinarySecurityToken',
                                namespaces={'soapenv': ns.SOAP_ENV_11, 'wsse': ns.WSSE})[0]
        ref = envelope.xpath('soapenv:Header/wsse:Security/ds:Signature/ds:KeyInfo/wsse:SecurityTokenReference'
                             '/wsse:Reference',
                             namespaces={'soapenv': ns.SOAP_ENV_11, 'wsse': ns.WSSE, 'ds': ns.DS})[0]
        self.assertEqual('#' + bintok.attrib[QName(ns.WSU, 'Id')], ref.attrib['URI'])


class TestMemorySignature(TestCase):
    """Unittests for MemorySignature."""

    def test_signature(self):
        with open(KEY_FILE) as key, open(CERT_FILE) as cert:
            plugin = MemorySignature(key.read(), cert.read())
        envelope, headers = plugin.apply(load_xml(ENVELOPE), {})
        plugin.verify(envelope)

    def test_verify_no_header(self):
        plugin = MemorySignature(open(KEY_FILE).read(), open(CERT_FILE).read())
        with self.assertRaises(SignatureVerificationFailed):
            plugin.verify(load_xml(
                """
                <soapenv:Envelope xmlns:tns="http://tests.python-zeep.org/"
                xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
                xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/">
                    <soapenv:Body>
                        <tns:Function>
                            <tns:Argument>OK</tns:Argument>
                        </tns:Function>
                    </soapenv:Body>
                </soapenv:Envelope>
                """))

    def test_verify_no_security(self):
        plugin = MemorySignature(open(KEY_FILE).read(), open(CERT_FILE).read())
        with self.assertRaises(SignatureVerificationFailed):
            plugin.verify(load_xml(ENVELOPE))

    def test_verify_no_signature(self):
        plugin = MemorySignature(open(KEY_FILE).read(), open(CERT_FILE).read())
        plugin.verify(load_xml(
            """
            <soapenv:Envelope xmlns:tns="http://tests.python-zeep.org/" xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
            xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
            xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/">
                <soapenv:Header>
                    <wsse:Security
                    xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                    </wsse:Security>
                </soapenv:Header>
                <soapenv:Body>
                    <tns:Function>
                        <tns:Argument>OK</tns:Argument>
                    </tns:Function>
                </soapenv:Body>
            </soapenv:Envelope>
            """))


class TestSignature(TestCase):
    """Unittests for Signature."""

    def test_signature(self):
        plugin = Signature(KEY_FILE, CERT_FILE)
        envelope, headers = plugin.apply(load_xml(ENVELOPE), {})
        plugin.verify(envelope)


class TestSAMLTokenSignature(TestCase):
    """Unittests dof SAMLTokenSignature."""

    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), 'assertion.xml')) as f:
            self.assertion = load_xml(f.read())

    def test_signature_saml(self):
        plugin = SAMLTokenSignature(self.assertion)
        envelope, headers = plugin.apply(load_xml(ENVELOPE), {})
        plugin.verify(envelope)
