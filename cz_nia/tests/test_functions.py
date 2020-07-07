"""Unittets for functions module."""
import datetime
import os
from unittest import TestCase

import responses
from lxml.etree import fromstring
from zeep.transports import Transport

from cz_nia.exceptions import NiaException
from cz_nia.functions import (_call_federation, _call_identity, _call_submission, change_authenticator,
                              get_notification, get_pseudonym, write_authenticator)
from cz_nia.message import IdentificationMessage
from cz_nia.settings import CzNiaAppSettings

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
            token = _call_identity(SETTINGS, TRANSPORT)
            self.assertEqual(token.attrib['AssertionID'], '_bd0832fa-ac6c-49ed-b50b-d1b309a1745d')
            self.assertEqual(token.tag, '{urn:oasis:names:tc:SAML:1.0:assertion}Assertion')


class TestCallFederation(TestCase):
    """Unittests for _call_federation function."""

    def test_error(self):
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/FPSTS/Issue.svc',
                     body=file_content('Err_response.xml'))
            with self.assertRaises(NiaException) as err:
                _call_federation(SETTINGS, TRANSPORT, fromstring(file_content('fp_token.xml')))
            self.assertIn('The server was unable to process', str(err.exception))

    def test_token(self):
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/FPSTS/Issue.svc',
                     body=file_content('FPSTS_response.xml'))
            token = _call_federation(SETTINGS, TRANSPORT, fromstring(file_content('fp_token.xml')))
            self.assertEqual(token.attrib['AssertionID'], '_685a595d-fd20-426e-94dd-a9f101a37854')
            self.assertEqual(token.tag, '{urn:oasis:names:tc:SAML:1.0:assertion}Assertion')


class TestCallSubmission(TestCase):
    """Unittests for _call_submission function."""

    def test_error(self):
        message = IdentificationMessage({'first_name': 'Eda', 'last_name': 'Tester',
                                         'birth_date': datetime.date(2000, 5, 1)})
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/WS/submission/Public.svc/token',
                     body=file_content('Err_response.xml'))
            with self.assertRaises(NiaException) as err:
                _call_submission(SETTINGS, TRANSPORT, fromstring(file_content('sub_token.xml')), message)
            self.assertIn('The server was unable to process', str(err.exception))

    def test_token(self):
        message = IdentificationMessage({'first_name': 'Eda', 'last_name': 'Tester',
                                         'birth_date': datetime.date(2000, 5, 1)})
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/WS/submission/Public.svc/token',
                     body=file_content('Sub_response.xml'))
            body = _call_submission(SETTINGS, TRANSPORT, fromstring(file_content('sub_token.xml')), message)
            parsed = fromstring(body)
            self.assertEqual([child.text for child in parsed.getchildren()[0].getchildren()[0].getchildren()],
                             ['1d71ff1a-d732-4485-a8dc-ad4c42a8a739', 'OK', None, 'DANIEL', u'KA\u0160P\xc1REK',
                              '4825055', '1988-05-21'])


class TestGetPseudonym(TestCase):
    """Unittests for get_pseudonym function."""

    def test_pseudonym(self):
        user_data = {'first_name': 'Eda', 'last_name': 'Tester',
                     'birth_date': datetime.date(2000, 5, 1)}
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/IPSTS/issue.svc/certificate',
                     body=file_content('IPSTS_response.xml'))
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/FPSTS/Issue.svc',
                     body=file_content('FPSTS_response.xml'))
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/WS/submission/Public.svc/token',
                     body=file_content('Sub_response.xml'))
            self.assertEqual(get_pseudonym(SETTINGS, user_data), '1d71ff1a-d732-4485-a8dc-ad4c42a8a739')

    def test_no_data(self):
        user_data = {'first_name': 'Eda', 'last_name': 'Tester',
                     'birth_date': datetime.date(2000, 5, 1)}
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/IPSTS/issue.svc/certificate',
                     body=file_content('IPSTS_response.xml'))
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/FPSTS/Issue.svc',
                     body=file_content('FPSTS_response.xml'))
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/WS/submission/Public.svc/token',
                     body=file_content('Sub_empty_response.xml'))
            with self.assertRaises(NiaException) as err:
                get_pseudonym(SETTINGS, user_data)
            self.assertEqual(str(err.exception), 'ISZR returned zero AIFOs')


class TestWriteAuthenticator(TestCase):
    """Unittests for write_authenticator function."""

    def test_write_authenticator(self):
        data = {'pseudonym': '1d71ff1a-d732-4485-a8dc-ad4c42a8a739', 'identification': 'vip_identification',
                'level_of_authentication': 'High'}
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/IPSTS/issue.svc/certificate',
                     body=file_content('IPSTS_response.xml'))
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/FPSTS/Issue.svc',
                     body=file_content('FPSTS_response.xml'))
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/WS/submission/Public.svc/token',
                     body=file_content('write_vip.xml'))
            write_authenticator(SETTINGS, data)

    def test_write_authenticator_error(self):
        data = {'pseudonym': '1d71ff1a-d732-4485-a8dc-ad4c42a8a739', 'identification': 'vip_identification',
                'level_of_authentication': 'High'}
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/IPSTS/issue.svc/certificate',
                     body=file_content('IPSTS_response.xml'))
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/FPSTS/Issue.svc',
                     body=file_content('FPSTS_response.xml'))
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/WS/submission/Public.svc/token',
                     body=file_content('write_vip_err.xml'))
            with self.assertRaises(NiaException) as err:
                write_authenticator(SETTINGS, data)
            self.assertEqual(str(err.exception), 'Identification record already exists')


class TestChangeAuthenticator(TestCase):
    """Unittests for change_authenticator function."""

    def test_change_authenticator(self):
        data = {'pseudonym': '1d71ff1a-d732-4485-a8dc-ad4c42a8a739', 'identification': 'vip_identification',
                'state': 'Aktivni', 'level_of_authentication': 'High'}
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/IPSTS/issue.svc/certificate',
                     body=file_content('IPSTS_response.xml'))
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/FPSTS/Issue.svc',
                     body=file_content('FPSTS_response.xml'))
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/WS/submission/Public.svc/token',
                     body=file_content('change_vip.xml'))
            change_authenticator(SETTINGS, data)

    def test_change_authenticator_error(self):
        data = {'pseudonym': '1d71ff1a-d732-4485-a8dc-ad4c42a8a739', 'identification': 'vip_identification',
                'state': 'Aktivni', 'level_of_authentication': 'High'}
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/IPSTS/issue.svc/certificate',
                     body=file_content('IPSTS_response.xml'))
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/FPSTS/Issue.svc',
                     body=file_content('FPSTS_response.xml'))
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/WS/submission/Public.svc/token',
                     body=file_content('change_vip_err.xml'))
            with self.assertRaises(NiaException) as err:
                change_authenticator(SETTINGS, data)
            self.assertEqual(str(err.exception), 'Required record does not exists')


class TestGetNotification(TestCase):
    """Unittests for get_notification."""

    def test_get_notification(self):
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/IPSTS/issue.svc/certificate',
                     body=file_content('IPSTS_response.xml'))
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/FPSTS/Issue.svc',
                     body=file_content('FPSTS_response.xml'))
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/WS/submission/Public.svc/token',
                     body=file_content('notifications.xml'))
            notifications = get_notification(SETTINGS)
        self.assertFalse(notifications.more_notifications)
        self.assertIsNone(notifications.last_id)
        self.assertEqual(len(notifications.notifications), 12)
        self.assertEqual(notifications.notifications[0],
                         {'source': 'ROBREF',
                          'id': '11612',
                          'pseudonym': 'ca8ff536-3d6c-42ce-a33f-c19e5377b6ab',
                          'message': 'Změna referenčních údajů ROB.',
                          'datetime': datetime.datetime(2020, 4, 1, 7, 1, 4, 890000),
                          'address': '76210',
                          'given_name': 'JULIE',
                          'last_name': 'VALIHRACHOVÁ'})
        self.assertEqual(notifications.notifications[1],
                         {'id': '11627',
                          'pseudonym': 'a12bc421-23df-4f1b-b896-3df6f23f2cf8',
                          'source': 'EVPROST',
                          'message': 'Aktualizace stavu identifikátoru prostředku pro elektronickou identifikaci',
                          'datetime': datetime.datetime(2020, 4, 1, 15, 9, 31, 693000)})
        self.assertEqual(notifications.notifications[7],
                         {'id': '11651',
                          'pseudonym': 'b0901628-4529-4382-b84f-5c649df0393c',
                          'source': 'ROBREF',
                          'datetime': datetime.datetime(2020, 4, 5, 7, 0, 24, 30000),
                          'message': 'Změna referenčních údajů ROB.',
                          'address': '264',
                          'date_of_birth': '1981-09-13',
                          'given_name': 'KAREL',
                          'last_name': 'MAJER'})

    def test_get_notification_error(self):
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/IPSTS/issue.svc/certificate',
                     body=file_content('IPSTS_response.xml'))
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/FPSTS/Issue.svc',
                     body=file_content('FPSTS_response.xml'))
            rsps.add(responses.POST, 'https://tnia.eidentita.cz/WS/submission/Public.svc/token',
                     body=file_content('notification_error.xml'))
            with self.assertRaises(NiaException) as err:
                get_notification(SETTINGS)
            self.assertEqual(str(err.exception), 'General Error. See log for more details')
