"""Unittests for messages."""
import datetime
from unittest import TestCase

from lxml.etree import QName

from cz_nia import NIAException
from cz_nia.message import ZtotozneniMessage, NotifikaceMessage, ZneplatnenePseudonymyMessage

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
        with self.assertRaisesRegexp(NIAException, 'Error parsing request'):
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


class TestNotifikaceMessage(TestCase):
    """Unittests for Notifikace message."""

    def test_parse_error(self):
        content = '<NotifikaceIdpResponse xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
                   xmlns:xsd="http://www.w3.org/2001/XMLSchema" \
                   xmlns="urn:nia.notifikaceIdp/response:v1"> \
                   <Status>Error</Status> \
                   <Detail>General Error. See log for more details</Detail> \
                   </NotifikaceIdpResponse>'
        response = BASE_BODY.format(CONTENT=content)
        with self.assertRaisesRegexp(NIAException, 'General Error. See log for more details'):
            NotifikaceMessage(None).unpack(response)

    def test_parse_success_empty(self):
        content = '<NotifikaceIdpResponse xmlns="urn:nia.notifikaceIdp/response:v1" \
                   xmlns:xsd="http://www.w3.org/2001/XMLSchema" \
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"> \
                   <Status>OK</Status> \
                   <Detail>Nebyly nalezeny \xc5\xbe\xc3\xa1dn\xc3\xa9 notifikace</Detail> \
                   <SeznamNotifikaceIdp /> \
                   </NotifikaceIdpResponse>'
        response = BASE_BODY.format(CONTENT=content)
        self.assertEqual(NotifikaceMessage(None).unpack(response), {'last_id': None, 'more_notifications': False,
                                                                    'notifications': []})

    def test_parse_success_list(self):
        content = '<NotifikaceIdpResponse xmlns="urn:nia.notifikaceIdp/response:v1" \
                   xmlns:xsd="http://www.w3.org/2001/XMLSchema" \
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"> \
                   <Status>OK</Status> \
                   <SeznamNotifikaceIdp> \
                   <NotifikaceIdp> \
                   <NotifikaceIdpId>132</NotifikaceIdpId> \
                   <Bsi>some_pseudonym</Bsi> \
                   <DatumACasNotifikace>2017-12-07T14:41:01.787</DatumACasNotifikace> \
                   <Zdroj>ROBREF</Zdroj> \
                   <Text>Zmena referencních údaju ROB.</Text> \
                   </NotifikaceIdp> \
                   </SeznamNotifikaceIdp> \
                   <NotifikaceIdpPosledniId>133</NotifikaceIdpPosledniId> \
                   <ExistujiDalsiNotifikace>true</ExistujiDalsiNotifikace> \
                   </NotifikaceIdpResponse>'
        response = BASE_BODY.format(CONTENT=content)
        expected = {'last_id': '133',
                    'more_notifications': True,
                    'notifications': [{'Id': '132', 'Pseudonym': 'some_pseudonym', 'Source': 'ROBREF'}]}
        self.assertEqual(NotifikaceMessage(None).unpack(response), expected)


class TestZneplatnenePseudonymyMessage(TestCase):
    """Unittests for ZneplatnenePseudonymyMessage."""

    def test_parse_error(self):
        content = '<ZneplatnenePseudonymyResponse xmlns:xsd="htp://www.w3.org/2001/XMLSchema" \
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
                   xmlns="urn:nia.zneplatnenePseudonymy/response:v1"> \
                   <Status>Error</Status> \
                   <Detail>Invalid combination of request parameters</Detail> \
                   </ZneplatnenePseudonymyResponse>'
        response = BASE_BODY.format(CONTENT=content)
        with self.assertRaisesRegexp(NIAException, 'Invalid combination of request parameters'):
            ZneplatnenePseudonymyMessage(None).unpack(response)

    def test_parse_success(self):
        content = '<ZneplatnenePseudonymyResponse xmlns:xsd="htp://www.w3.org/2001/XMLSchema" \
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
                   xmlns="urn:nia.zneplatnenePseudonymy/response:v1"> \
                   <Pseudonyms> \
                   <Pseudonym> \
                   <Id>some_pseudonym</Id> \
                   <Zneplatneno>2016-06-15T15:58:50.719248+02:00</Zneplatneno> \
                   </Pseudonym> \
                   </Pseudonyms> \
                   <Status>OK</Status> \
                   <Interval> \
                   <DatumOd>2016-06-15T14:33:41.9753822+02:00</DatumOd> \
                   <DatumDo>2016-06-15T16:07:09.6647232+02:00</DatumDo> \
                   </Interval> \
                   </ZneplatnenePseudonymyResponse>'
        response = BASE_BODY.format(CONTENT=content)
        self.assertEqual(ZneplatnenePseudonymyMessage(None).unpack(response),
                         [{'Pseudonym': 'some_pseudonym', 'date': '2016-06-15T15:58:50.719248+02:00'}])
