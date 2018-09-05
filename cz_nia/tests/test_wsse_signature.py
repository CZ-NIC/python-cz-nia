"""Unittests for wsse.signature module."""
import os
from unittest import TestCase

from cz_nia.tests.utils import load_xml
from cz_nia.wsse import BinarySignature, MemorySignature, SAMLTokenSignature, Signature

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
