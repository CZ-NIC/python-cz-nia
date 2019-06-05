"""Unittests for messages."""
import datetime
from unittest import TestCase

from lxml.etree import QName

from cz_nia.exceptions import NiaException
from cz_nia.message import ZtotozneniMessage

BASE_BODY = '<bodies xmlns="http://www.government-gateway.cz/wcf/submission">\
             <Body Id="0" xmlns="http://www.govtalk.gov.uk/CM/envelope"> \
             {CONTENT} \
             </Body> \
             </bodies>'


class TestZtotozneniMessage(TestCase):
    """Unittests for Ztotozneni message."""

    def test_parse_error(self):
        content = '<ZtotozneniResponse xmlns:xsd="http://www.w3.org/2001/XMLSchema" \
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
                   xmlns="urn:nia.ztotozneni/response:v4"> \
                   <Status>Error</Status> \
                   <Detail>Error parsing request</Detail> \
                   </ZtotozneniResponse>'
        response = BASE_BODY.format(CONTENT=content)
        with self.assertRaisesRegexp(NiaException, 'Error parsing request'):
            ZtotozneniMessage('').unpack(response)

    def test_parse_success(self):
        content = '<ZtotozneniResponse xmlns:xsd="http://www.w3.org/2001/XMLSchema" \
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
                   xmlns="urn:nia.ztotozneni/response:v4"> \
                   <Status>OK</Status> \
                   <Pseudonym>this is pseudonym</Pseudonym> \
                   </ZtotozneniResponse>'
        response = BASE_BODY.format(CONTENT=content)
        self.assertEqual(ZtotozneniMessage('').unpack(response), 'this is pseudonym')

    def test_pack(self):
        message = ZtotozneniMessage({'first_name': 'Eda', 'last_name': 'Tester',
                                     'birth_date': datetime.date(2000, 5, 1)}).pack()
        namespace = 'urn:nia.ztotozneni/request:v3'
        expected = {
            QName(namespace, 'Jmeno'): 'Eda',
            QName(namespace, 'Prijmeni'): 'Tester',
            QName(namespace, 'TypPorovnani'): 'diakritika',
            QName(namespace, 'DatumNarozeni'): '2000-05-01',
        }
        self.assertEqual(message.nsmap.get(message.prefix), namespace)
        for child in message.iterchildren():
            self.assertEqual(child.text, expected[child.tag])
