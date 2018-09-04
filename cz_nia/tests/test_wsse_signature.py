"""Unittests for wsse.signature module."""
import os
from unittest import TestCase

from cz_nia.tests.utils import load_xml
from cz_nia.wsse import BinarySignature, SAMLTokenSignature

CERT_FILE = os.path.join(os.path.dirname(__file__), 'certificate.pem')
KEY_FILE = os.path.join(os.path.dirname(__file__), 'key.pem')


class TestBinarySignature(TestCase):
    """Unittests for BinarySignature."""

    def setUp(self):
        self.envelope = load_xml(
            """
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
            """)

    def test_signature_binary(self):
        plugin = BinarySignature(KEY_FILE, CERT_FILE)
        envelope, headers = plugin.apply(self.envelope, {})
        plugin.verify(envelope)


class TestSAMLTokenSignature(TestCase):
    """Unittests dof SAMLTokenSignature."""

    def setUp(self):
        self.envelope = load_xml(
            """
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
            """)
        self.assertion = load_xml(open(os.path.join(os.path.dirname(__file__), 'assertion.xml')).read())

    def test_signature_saml(self):
        plugin = SAMLTokenSignature(self.assertion)
        envelope, headers = plugin.apply(self.envelope, {})
        plugin.verify(envelope)
