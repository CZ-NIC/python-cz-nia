"""Unittests for CzNiaAppSettings."""
import os
from unittest import TestCase

from cz_nia.settings import CzNiaAppSettings

BASENAME = os.path.join(os.path.dirname(__file__), 'data')


class TestCzNiaAppSettings(TestCase):
    """Unittests for CzNiaAppSettings."""

    def test_cache_path_none(self):
        settings = CzNiaAppSettings({
            'identity_wsdl': 'file://' + os.path.join(BASENAME, 'IPSTS_nice.wsdl'),
            'federation_wsdl': 'file://' + os.path.join(BASENAME, 'FPSTS_nice.wsdl'),
            'public_wsdl': 'file://' + os.path.join(BASENAME, 'Public_nice.wsdl'),
            'federation_address': 'https://tnia.eidentita.cz/FPSTS/issue.svc',
            'public_address': 'https://tnia.eidentita.cz/ws/submission/public.svc/token',
            'certificate': os.path.join(BASENAME, 'NIA.pem'),
            'key': os.path.join(BASENAME, 'NIA.pem'),
            'password': None}
        )
        self.assertIsNone(settings.CACHE_PATH)

    def test_cache_path(self):
        settings = CzNiaAppSettings({
            'identity_wsdl': 'file://' + os.path.join(BASENAME, 'IPSTS_nice.wsdl'),
            'federation_wsdl': 'file://' + os.path.join(BASENAME, 'FPSTS_nice.wsdl'),
            'public_wsdl': 'file://' + os.path.join(BASENAME, 'Public_nice.wsdl'),
            'federation_address': 'https://tnia.eidentita.cz/FPSTS/issue.svc',
            'public_address': 'https://tnia.eidentita.cz/ws/submission/public.svc/token',
            'certificate': os.path.join(BASENAME, 'NIA.pem'),
            'key': os.path.join(BASENAME, 'NIA.pem'),
            'cache_path': os.path.join(BASENAME, 'cache'),
            'password': None}
        )
        self.assertEqual(settings.CACHE_PATH, str(os.path.join(BASENAME, 'cache')))
