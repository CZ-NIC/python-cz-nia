"""Unittests for messages."""
import datetime
from unittest import TestCase

from lxml.etree import DocumentInvalid, Element, QName, SubElement, fromstring

from cz_nia.exceptions import NiaException
from cz_nia.message import (ChangeAuthenticatorMessage, IdentificationMessage, NiaMessage, NotificationMessage,
                            WriteAuthenticatorMessage)

BASE_BODY = '<bodies xmlns="http://www.government-gateway.cz/wcf/submission">\
             <Body Id="0" xmlns="http://www.govtalk.gov.uk/CM/envelope"> \
             {CONTENT} \
             </Body> \
             </bodies>'


class NiaMessageTestClass(NiaMessage):
    """Message for tests."""

    request_namespace = 'request_namespace'
    response_namespace = 'response_namespace'
    response_class = 'response_class'
    action = 'action'
    xmlschema_definition = '../tests/data/test_schema.xsd'

    def create_message(self):
        payload = Element(QName('request_namespace', 'request'))
        content = SubElement(payload, QName('request_namespace', 'content'))
        content.text = self.data.get('content')
        return payload

    def extract_message(self, response):
        return 'parsed'


class TestNiaMessage(TestCase):
    """Unittests for NiaMessage using NiaMessageTestClass."""

    def test_get_namespace_map(self):
        message = NiaMessageTestClass('')
        self.assertEqual(message.get_namespace_map, {'gov': message.govtalk_namespace, 'nia': 'response_namespace'})

    def test_validate(self):
        payload = Element(QName('request_namespace', 'request'))
        content = SubElement(payload, QName('request_namespace', 'content'))
        content.text = 'something'
        message = NiaMessageTestClass('')
        message.validate(payload)

    def test_validate_error(self):
        payload = Element(QName('request_namespace', 'request'))
        SubElement(payload, QName('request_namespace', 'invalid'))
        message = NiaMessageTestClass('')
        with self.assertRaises(DocumentInvalid):
            message.validate(payload)

    def test_pack(self):
        message = NiaMessageTestClass({'content': 'something'}).pack()
        self.assertEqual(message.tag, QName('request_namespace', 'request'))
        children = message.getchildren()
        self.assertEqual(len(children), 1)
        self.assertEqual(children[0].tag, QName('request_namespace', 'content'))
        self.assertEqual(children[0].text, 'something')

    def test_unpack(self):
        content = '<response_class xmlns:xsd="http://www.w3.org/2001/XMLSchema" \
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
                   xmlns="response_namespace"> \
                   <Status>OK</Status> \
                   </response_class>'
        response = BASE_BODY.format(CONTENT=content).encode()
        self.assertEqual(NiaMessageTestClass('').unpack(response), 'parsed')

    def test_verify_message(self):
        content = '<response_class xmlns:xsd="http://www.w3.org/2001/XMLSchema" \
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
                   xmlns="response_namespace"> \
                   <Status>OK</Status> \
                   <Pseudonym>this is pseudonym</Pseudonym> \
                   </response_class>'
        response = BASE_BODY.format(CONTENT=content).encode()
        namespace = 'response_namespace'
        message = NiaMessageTestClass('').verify_message(response)
        expected = {
            QName(namespace, 'Status'): 'OK',
            QName(namespace, 'Pseudonym'): 'this is pseudonym',
        }
        self.assertEqual(message.nsmap.get(message.prefix), namespace)
        for child in message.iterchildren():
            self.assertEqual(child.text, expected[child.tag])

    def test_verify_message_error(self):
        content = '<response_class xmlns:xsd="http://www.w3.org/2001/XMLSchema" \
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
                   xmlns="response_namespace"> \
                   <Status>Error</Status> \
                   <Detail>Error parsing request</Detail> \
                   </response_class>'
        response = BASE_BODY.format(CONTENT=content).encode()
        with self.assertRaises(NiaException):
            NiaMessageTestClass('').verify_message(response)


class TestIdentificationMessage(TestCase):
    """Unittests for IdentificationMessage."""

    def test_extract_message(self):
        content = '<ZtotozneniResponse xmlns:xsd="http://www.w3.org/2001/XMLSchema" \
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
                   xmlns="urn:nia.ztotozneni/response:v4"> \
                   <Status>OK</Status> \
                   <Pseudonym>this is pseudonym</Pseudonym> \
                   </ZtotozneniResponse>'
        response = fromstring(BASE_BODY.format(CONTENT=content).encode())
        body = response.find('gov:Body/nia:ZtotozneniResponse', namespaces=IdentificationMessage('').get_namespace_map)
        self.assertEqual(IdentificationMessage('').extract_message(body), 'this is pseudonym')

    def test_create_message(self):
        message = IdentificationMessage({'first_name': 'Eda', 'last_name': 'Tester',
                                         'birth_date': datetime.date(2000, 5, 1)}).create_message()
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

    def test_create_message_address(self):
        message = IdentificationMessage({'first_name': 'Eda', 'last_name': 'Tester',
                                         'birth_date': datetime.date(2000, 5, 1), 'address': '1'}).create_message()
        namespace = 'urn:nia.ztotozneni/request:v3'
        expected = {
            QName(namespace, 'AdresaPobytu'): '1',
            QName(namespace, 'Jmeno'): 'Eda',
            QName(namespace, 'Prijmeni'): 'Tester',
            QName(namespace, 'TypPorovnani'): 'diakritika',
            QName(namespace, 'DatumNarozeni'): '2000-05-01',
        }
        self.assertEqual(message.nsmap.get(message.prefix), namespace)
        for child in message.iterchildren():
            self.assertEqual(child.text, expected[child.tag])


class TestWriteAuthenticatorMessage(TestCase):
    """Unittests for WriteAuthenticatorMessage."""

    def test_create_message_unverified(self):
        message = WriteAuthenticatorMessage({'identification': 'some_vip', 'level_of_authentication': 'High',
                                             'verified': 'false', 'pseudonym': 'some_pseudonym'}).create_message()
        namespace = 'urn:nia.EvidenceVIPZapis/request:v2'
        expected = {
            QName(namespace, 'Bsi'): 'some_pseudonym',
            QName(namespace, 'IdentifikaceProstredku'): 'some_vip',
            QName(namespace, 'LoA'): 'High',
            QName(namespace, 'OverenoDoklademTotoznosti'): 'false',
        }
        self.assertEqual(message.nsmap.get(message.prefix), namespace)
        for child in message.iterchildren():
            self.assertEqual(child.text, expected[child.tag])

    def test_create_message_verified(self):
        message = WriteAuthenticatorMessage({'identification': 'some_vip', 'level_of_authentication': 'High',
                                             'verified': 'true', 'pseudonym': 'some_pseudonym',
                                             'id_data': {'number': '42', 'type': 'P'}}).create_message()
        namespace = 'urn:nia.EvidenceVIPZapis/request:v2'
        expected = {
            QName(namespace, 'Bsi'): 'some_pseudonym',
            QName(namespace, 'IdentifikaceProstredku'): 'some_vip',
            QName(namespace, 'LoA'): 'High',
            QName(namespace, 'OverenoDoklademTotoznosti'): 'true',
            QName(namespace, 'PrukazTotoznosti'): None,
        }
        self.assertEqual(message.nsmap.get(message.prefix), namespace)
        for child in message.iterchildren():
            self.assertEqual(child.text, expected[child.tag])
        id_card = message.find(QName(namespace, 'PrukazTotoznosti'))
        expected_card = {
            QName(namespace, 'Cislo'): '42',
            QName(namespace, 'Druh'): 'P',
        }
        for child in id_card.iterchildren():
            self.assertEqual(child.text, expected_card[child.tag])

    def test_create_message_state(self):
        message = WriteAuthenticatorMessage({'identification': 'some_vip', 'level_of_authentication': 'High',
                                             'verified': 'false', 'pseudonym': 'some_pseudonym',
                                             'state': 'Aktivni'}).create_message()
        namespace = 'urn:nia.EvidenceVIPZapis/request:v2'
        expected = {
            QName(namespace, 'Bsi'): 'some_pseudonym',
            QName(namespace, 'IdentifikaceProstredku'): 'some_vip',
            QName(namespace, 'LoA'): 'High',
            QName(namespace, 'OverenoDoklademTotoznosti'): 'false',
            QName(namespace, 'Stav'): 'Aktivni',
        }
        self.assertEqual(message.nsmap.get(message.prefix), namespace)
        for child in message.iterchildren():
            self.assertEqual(child.text, expected[child.tag])


class TestChangeAuthenticatorMessage(TestCase):
    """Unittests for ChangeAuthenticatorMessage."""

    def test_create_message(self):
        message = ChangeAuthenticatorMessage({'identification': 'some_vip', 'level_of_authentication': 'High',
                                              'state': 'Aktivni', 'pseudonym': 'some_pseudonym',
                                              'message': 'some message to the authorities'}).create_message()
        namespace = 'urn:nia.EvidenceVIPZmena/request:v1'
        expected = {
            QName(namespace, 'Bsi'): 'some_pseudonym',
            QName(namespace, 'IdentifikaceProstredku'): 'some_vip',
            QName(namespace, 'LoA'): 'High',
            QName(namespace, 'Stav'): 'Aktivni',
            QName(namespace, 'Zprava'): 'some message to the authorities',
        }
        self.assertEqual(message.nsmap.get(message.prefix), namespace)
        for child in message.iterchildren():
            self.assertEqual(child.text, expected[child.tag])


class TestNotificationMessage(TestCase):
    """Unittests for Notifikace message."""

    def test_extract_message_error(self):
        content = '<NotifikaceIdpResponse xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
                   xmlns:xsd="http://www.w3.org/2001/XMLSchema" \
                   xmlns="urn:nia.notifikaceIdp/response:v1"> \
                   <Status>Error</Status> \
                   <Detail>General Error. See log for more details</Detail> \
                   </NotifikaceIdpResponse>'
        response = fromstring(BASE_BODY.format(CONTENT=content).encode())
        body = response.find('gov:Body/nia:NotifikaceIdpResponse', namespaces=NotificationMessage('').get_namespace_map)
        response = NotificationMessage(None).extract_message(body)
        self.assertEqual(response.notifications, [])
        self.assertIsNone(response.last_id)
        self.assertFalse(response.more_notifications)

    def test_parse_success_empty(self):
        content = '<NotifikaceIdpResponse xmlns="urn:nia.notifikaceIdp/response:v1" \
                   xmlns:xsd="http://www.w3.org/2001/XMLSchema" \
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"> \
                   <Status>OK</Status> \
                   <Detail>Nebyly nalezeny \xc5\xbe\xc3\xa1dn\xc3\xa9 notifikace</Detail> \
                   <SeznamNotifikaceIdp /> \
                   </NotifikaceIdpResponse>'
        response = fromstring(BASE_BODY.format(CONTENT=content).encode())
        body = response.find('gov:Body/nia:NotifikaceIdpResponse', namespaces=NotificationMessage('').get_namespace_map)
        response = NotificationMessage(None).extract_message(body)
        self.assertEqual(response.notifications, [])
        self.assertIsNone(response.last_id)
        self.assertFalse(response.more_notifications)

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
        response = fromstring(BASE_BODY.format(CONTENT=content).encode())
        body = response.find('gov:Body/nia:NotifikaceIdpResponse', namespaces=NotificationMessage('').get_namespace_map)
        response = NotificationMessage(None).extract_message(body)
        self.assertEqual(response.notifications, [{'id': '132', 'pseudonym': 'some_pseudonym', 'source': 'ROBREF',
                                                   'message': 'Zmena referencních údaju ROB.',
                                                   'datetime': datetime.datetime(2017, 12, 7, 14, 41, 1, 787000)}])
        self.assertEqual(response.last_id, 133)
        self.assertTrue(response.more_notifications)

    def test_parse_success_no_micro(self):
        content = '<NotifikaceIdpResponse xmlns="urn:nia.notifikaceIdp/response:v1" \
                   xmlns:xsd="http://www.w3.org/2001/XMLSchema" \
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"> \
                   <Status>OK</Status> \
                   <SeznamNotifikaceIdp> \
                   <NotifikaceIdp> \
                   <NotifikaceIdpId>132</NotifikaceIdpId> \
                   <Bsi>some_pseudonym</Bsi> \
                   <DatumACasNotifikace>2017-12-07T14:41:01</DatumACasNotifikace> \
                   <Zdroj>ROBREF</Zdroj> \
                   <Text>Zmena referencních údaju ROB.</Text> \
                   </NotifikaceIdp> \
                   </SeznamNotifikaceIdp> \
                   <NotifikaceIdpPosledniId>133</NotifikaceIdpPosledniId> \
                   <ExistujiDalsiNotifikace>true</ExistujiDalsiNotifikace> \
                   </NotifikaceIdpResponse>'
        response = fromstring(BASE_BODY.format(CONTENT=content).encode())
        body = response.find('gov:Body/nia:NotifikaceIdpResponse', namespaces=NotificationMessage('').get_namespace_map)
        response = NotificationMessage(None).extract_message(body)
        self.assertEqual(response.notifications, [{'id': '132', 'pseudonym': 'some_pseudonym', 'source': 'ROBREF',
                                                   'message': 'Zmena referencních údaju ROB.',
                                                   'datetime': datetime.datetime(2017, 12, 7, 14, 41, 1)}])
        self.assertEqual(response.last_id, 133)
        self.assertTrue(response.more_notifications)

    def test_parse_success_unknown(self):
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
                   <ReferencniData> \
                   <UnknownTag>something</UnknownTag> \
                   </ReferencniData> \
                   </NotifikaceIdp> \
                   </SeznamNotifikaceIdp> \
                   <NotifikaceIdpPosledniId>133</NotifikaceIdpPosledniId> \
                   <ExistujiDalsiNotifikace>true</ExistujiDalsiNotifikace> \
                   </NotifikaceIdpResponse>'
        response = fromstring(BASE_BODY.format(CONTENT=content).encode())
        body = response.find('gov:Body/nia:NotifikaceIdpResponse', namespaces=NotificationMessage('').get_namespace_map)
        response = NotificationMessage(None).extract_message(body)
        self.assertEqual(response.notifications, [{'id': '132', 'pseudonym': 'some_pseudonym', 'source': 'ROBREF',
                                                   'message': 'Zmena referencních údaju ROB.',
                                                   'datetime': datetime.datetime(2017, 12, 7, 14, 41, 1, 787000),
                                                   '_UnknownTag': 'something'}])
        self.assertEqual(response.last_id, 133)
        self.assertTrue(response.more_notifications)

    def test_create_message(self):
        message = NotificationMessage(None).create_message()
        namespace = 'urn:nia.notifikaceIdp/request:v1'
        self.assertEqual(message.nsmap.get(message.prefix), namespace)
        self.assertEqual(len(message.getchildren()), 0)

    def test_pack_id(self):
        message = NotificationMessage({'id': 42}).create_message()
        namespace = 'urn:nia.notifikaceIdp/request:v1'
        self.assertEqual(message.nsmap.get(message.prefix), namespace)
        self.assertEqual(len(message.getchildren()), 1)
        self.assertEqual(message.find('nia:NotifikaceIdpId', namespaces={'nia': namespace}).text, '42')
