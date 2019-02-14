"""Messages for communication with NIA."""
from abc import ABC, abstractmethod

from lxml.etree import Element, QName, SubElement, fromstring

from cz_nia import NIAException


class NIAMessage(ABC):
    """Base class for messages."""

    # Common properties
    GOVTALK = 'http://www.govtalk.gov.uk/CM/envelope'
    # These are individual properties
    REQUEST_NAMESPACE = None
    RESPONSE_NAMESPACE = None
    RESPONSE_CLASS = None
    ACTION = None

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
        return {'gov': self.GOVTALK, 'nia': self.RESPONSE_NAMESPACE}

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
        response = body.find('gov:Body/nia:{}'.format(self.RESPONSE_CLASS), namespaces=nsmap)
        if response.find('nia:Status', namespaces=nsmap).text != 'OK':
            raise NIAException(response.find('nia:Detail', namespaces=nsmap).text)
        return response


class ZtotozneniMessage(NIAMessage):
    """Message for TR_ZTOTOZNENI."""

    REQUEST_NAMESPACE = 'urn:nia.ztotozneni/request:v3'
    RESPONSE_NAMESPACE = 'urn:nia.ztotozneni/response:v4'
    RESPONSE_CLASS = 'ZtotozneniResponse'
    ACTION = 'TR_ZTOTOZNENI'

    def pack(self):
        """Prepare the ZTOTOZNENI message with user data."""
        id_request = Element(QName(self.REQUEST_NAMESPACE, 'ZtotozneniRequest'))
        name = SubElement(id_request, QName(self.REQUEST_NAMESPACE, 'Jmeno'))
        name.text = self.data.get('first_name')
        surname = SubElement(id_request, QName(self.REQUEST_NAMESPACE, 'Prijmeni'))
        surname.text = self.data.get('last_name')
        date_of_birth = SubElement(id_request, QName(self.REQUEST_NAMESPACE, 'DatumNarozeni'))
        date_of_birth.text = self.data.get('birth_date').isoformat()
        compare_type = SubElement(id_request, QName(self.REQUEST_NAMESPACE, 'TypPorovnani'))
        compare_type.text = 'diakritika'
        return id_request

    def extract_message(self, response):
        """Get pseudonym from the message."""
        return response.find('nia:Pseudonym', namespaces=self.get_namespace_map).text


NIAMessage.register(ZtotozneniMessage)
