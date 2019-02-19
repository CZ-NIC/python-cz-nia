"""Messages for communication with NIA."""
from abc import ABC, abstractmethod

from lxml.etree import Element, QName, SubElement, fromstring

from cz_nia import NIAException


class NIAMessage(ABC):
    """Base class for messages."""

    govtalk_namespace = 'http://www.govtalk.gov.uk/CM/envelope'

    @property
    @abstractmethod
    def request_namespace(self):
        """Namespace of the request."""

    @property
    @abstractmethod
    def response_namespace(self):
        """Namespace of the rsponse."""

    @property
    @abstractmethod
    def response_class(self):
        """Class of the response."""

    @property
    @abstractmethod
    def action(self):
        """What action should be performed."""

    def __init__(self, data):
        """Store the data we want to pack."""
        self.data = data

    @abstractmethod
    def pack(self):
        """Pack the message containing data."""

    @abstractmethod
    def extract_message(self, message):
        """Extract relevant data from the message."""

    @property
    def get_namespace_map(self):
        """Return namespace map for the message."""
        return {'gov': self.govtalk_namespace, 'nia': self.response_namespace}

    def unpack(self, response):
        """Unpack the data from the response."""
        parsed_message = self.verify_message(response)
        return self.extract_message(parsed_message)

    def verify_message(self, message):
        """Verify the status of the message.

        Raises NIAException if the status is not OK.
        """
        body = fromstring(message)
        nsmap = self.get_namespace_map
        response = body.find('gov:Body/nia:{}'.format(self.response_class), namespaces=nsmap)
        if response.find('nia:Status', namespaces=nsmap).text != 'OK':
            raise NIAException(response.find('nia:Detail', namespaces=nsmap).text)
        return response


class ZtotozneniMessage(NIAMessage):
    """Message for TR_ZTOTOZNENI."""

    request_namespace = 'urn:nia.ztotozneni/request:v3'
    response_namespace = 'urn:nia.ztotozneni/response:v4'
    response_class = 'ZtotozneniResponse'
    action = 'TR_ZTOTOZNENI'

    def pack(self):
        """Prepare the ZTOTOZNENI message with user data."""
        id_request = Element(QName(self.request_namespace, 'ZtotozneniRequest'))
        name = SubElement(id_request, QName(self.request_namespace, 'Jmeno'))
        name.text = self.data.get('first_name')
        surname = SubElement(id_request, QName(self.request_namespace, 'Prijmeni'))
        surname.text = self.data.get('last_name')
        date_of_birth = SubElement(id_request, QName(self.request_namespace, 'DatumNarozeni'))
        date_of_birth.text = self.data.get('birth_date').isoformat()
        compare_type = SubElement(id_request, QName(self.request_namespace, 'TypPorovnani'))
        compare_type.text = 'diakritika'
        return id_request

    def extract_message(self, response):
        """Get pseudonym from the message."""
        return response.find('nia:Pseudonym', namespaces=self.get_namespace_map).text


class NotifikaceMessage(NIAMessage):
    """Message for TR_NOTIFIKACE_IDP."""

    request_namespace = 'urn:nia.notifikaceIdp/request:v1'
    response_namespace = 'urn:nia.notifikaceIdp/response:v1'
    response_class = 'NotifikaceIdpResponse'
    action = 'TR_NOTIFIKACE_IDP'

    def pack(self):
        """Prepare the NOTIFIKACE message."""
        id_request = Element(QName(self.request_namespace, 'NotifikaceIdpRequest'))
        if self.data is not None:
            idp_id = SubElement(id_request, QName(self.request_namespace, 'NotifikaceIdpId'))
            idp_id.text = self.data.get('id')
        return id_request

    def extract_message(self, response):
        """Get notifications from the message."""
        result = {'notifications': [], 'last_id': None, 'more_notifications': False}
        notifications = response.findall('nia:SeznamNotifikaceIdp/nia:NotifikaceIdp', namespaces=self.get_namespace_map)
        if not notifications:
            return result
        for notification in notifications:
            result['notifications'].append({
                'Id': notification.find('nia:NotifikaceIdpId', namespaces=self.get_namespace_map).text,
                'Pseudonym': notification.find('nia:Bsi', namespaces=self.get_namespace_map).text,
                'Source': notification.find('nia:Zdroj', namespaces=self.get_namespace_map).text,
            })
        result['last_id'] = response.find('nia:NotifikaceIdpPosledniId', namespaces=self.get_namespace_map).text
        result['more_notifications'] = response.find('nia:ExistujiDalsiNotifikace',
                                                     namespaces=self.get_namespace_map).text.lower() == 'true'
        return result


class EvidenceZapisMessage(NIAMessage):
    """Message for TR_EVIDENCE_VIP_ZAPIS."""

    request_namespace = 'urn:nia.EvidenceVIPZapis/request:v2'
    response_namespace = 'urn:nia.EvidenceVIPZapis/response:v1'
    response_class = 'EvidenceVIPZapisResponse'
    action = 'TR_EVIDENCE_VIP_ZAPIS'

    def pack(self):
        """Prepare the EVIDENCE_VIP_ZAPIS message."""
        id_request = Element(QName(self.request_namespace, 'EvidenceVIPZapisRequest'))
        bsi = SubElement(id_request, QName(self.request_namespace, 'Bsi'))
        bsi.text = self.data.get('pseudonym')
        id_prostr = SubElement(id_request, QName(self.request_namespace, 'IdentifikaceProstredku'))
        id_prostr.text = self.data.get('identification')
        loa = SubElement(id_request, QName(self.request_namespace, 'LoA'))
        loa.text = self.data.get('level_of_authentication')
        verified = SubElement(id_request, QName(self.request_namespace, 'OverenoDoklademTotoznosti'))
        verified.text = self.data.get('verified')
        if self.data.get('verified') and self.data.get('id_data'):
            # We have verified using an ID and have the correct data
            # TODO: Finish ...
            pass
        if self.data.get('state'):
            state = SubElement(id_request, QName(self.request_namespace, 'Stav'))
            state.text = self.data.get('state')
        return id_request

    def extract_message(self, response):
        """Do nothing."""
        return response


class EvidenceZmenaMessage(NIAMessage):
    """Message for TR_EVIDENCE_VIP_ZMENA."""

    request_namespace = 'urn:nia.EvidenceVIPZmena/request:v1'
    response_namespace = 'urn:nia.EvidenceVIPZmena/response:v1'
    response_class = 'EvidenceVIPZmenaResponse'
    action = 'TR_EVIDENCE_VIP_ZMENA'

    def pack(self):
        """Prepare the EVIDENCE_VIP_ZMENA message."""
        id_request = Element(QName(self.request_namespace, 'EvidenceVIPZmenaRequest'))
        bsi = SubElement(id_request, QName(self.request_namespace, 'Bsi'))
        bsi.text = self.data.get('pseudonym')
        id_prostr = SubElement(id_request, QName(self.request_namespace, 'IdentifikaceProstredku'))
        id_prostr.text = self.data.get('identification')
        loa = SubElement(id_request, QName(self.request_namespace, 'LoA'))
        loa.text = self.data.get('level_of_authentication')
        state = SubElement(id_request, QName(self.request_namespace, 'Stav'))
        state.text = self.data.get('state')

    def extract_message(self, response):
        """Do nothing."""
        return response


NIAMessage.register(ZtotozneniMessage)
NIAMessage.register(NotifikaceMessage)
NIAMessage.register(EvidenceZapisMessage)
NIAMessage.register(EvidenceZmenaMessage)
