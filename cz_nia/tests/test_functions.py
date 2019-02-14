"""Unittets for functions module."""
import responses
import os
from lxml.etree import fromstring
from cz_nia.settings import CzNiaAppSettings
from cz_nia.functions import _call_identity, _call_federation
from cz_nia.exceptions import NiaException
from unittest import TestCase
from zeep.transports import Transport


BASENAME = os.path.join(os.path.dirname(__file__), 'data')
SETTINGS = CzNiaAppSettings({
    'identity_wsdl': 'file://' + os.path.join(BASENAME, 'IPSTS_nice.wsdl'),
    'federation_wsdl': 'file://' + os.path.join(BASENAME, 'FPSTS_nice.wsdl'),
    'public_wsdl': 'file://' + os.path.join(BASENAME, 'Public_nice.wsdl'),
    'federation_address': 'https://tnia.eidentita.cz/FPSTS/issue.svc',
    'public_address': 'https://tnia.eidentita.cz/ws/submission/public.svc/token',
    'certificate': os.path.join(BASENAME, 'NIA.pem'),
    'key': os.path.join(BASENAME, 'NIA.pem'),
    'password': None}
)
TRANSPORT = Transport()


def file_content(filename):
    """Get file content."""
    with open(os.path.join(os.path.dirname(__file__), 'data', filename)) as f:
        return f.read()


class TestCallIdentity(TestCase):
    """Unittests for _call_identity function."""

    def test_error(self):
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/IPSTS/issue.svc/certificate',
                     body=file_content('Err_response.xml'))
            with self.assertRaises(NiaException) as err:
                _call_identity(SETTINGS, TRANSPORT)
            self.assertIn('The server was unable to process', str(err.exception))

    def test_token(self):
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/IPSTS/issue.svc/certificate',
                     body=file_content('IPSTS_response.xml'))
            token = _call_identity()
            self.assertEqual(token.attrib['AssertionID'], '_bd0832fa-ac6c-49ed-b50b-d1b309a1745d')
            self.assertEqual(token.tag, '{urn:oasis:names:tc:SAML:1.0:assertion}Assertion')


class TestCallFederation(TestCase):
    """Unittests for _call_federation function."""

    def test_error(self):
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/FPSTS/Issue.svc',
                     body=file_content('Err_response.xml'))
            with self.assertRaises(NiaException) as err:
                _call_federation(fromstring(file_content('fp_token.xml')))
            self.assertIn('The server was unable to process', str(err.exception))

    def test_token(self):
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/FPSTS/Issue.svc',
                     body=file_content('FPSTS_response.xml'))
            token = _call_federation(fromstring(file_content('fp_token.xml')))
            self.assertEqual(token.attrib['AssertionID'], '_685a595d-fd20-426e-94dd-a9f101a37854')
            self.assertEqual(token.tag, '{urn:oasis:names:tc:SAML:1.0:assertion}Assertion')


class TestGetPseudonym(TestCase):
    """Unittests for get_pseudonym function."""
