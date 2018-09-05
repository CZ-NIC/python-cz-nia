"""Unittests for wsse.signature module."""
import os
from unittest import TestCase

from lxml.etree import QName
from zeep import ns
from zeep.wsse.signature import _make_sign_key

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


class TestSignaturePrepare(TestCase):
    """Unittests for _signature_prepare."""

    def setUp(self):
        with open(KEY_FILE) as key, open(CERT_FILE) as cert:
            self.key = _make_sign_key(key.read(), cert.read(), None)

    def test_newline_strip(self):
        security, _, _ = _signature_prepare(load_xml(ENVELOPE), self.key)
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


class TestBinarySignature(TestCase):
    """Unittests for BinarySignature."""

    def test_signature_binary(self):
        plugin = BinarySignature(KEY_FILE, CERT_FILE)
        envelope, headers = plugin.apply(load_xml(ENVELOPE), {})
        plugin.verify(envelope)


class TestMemorySignature(TestCase):
    """Unittests for MemorySignature."""

    def test_signature(self):
        with open(KEY_FILE) as key, open(CERT_FILE) as cert:
            plugin = MemorySignature(key.read(), cert.read())
        envelope, headers = plugin.apply(load_xml(ENVELOPE), {})
        plugin.verify(envelope)


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
