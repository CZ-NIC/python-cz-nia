"""Messages for communication with NIA."""
from abc import ABC, abstractmethod
from typing import Dict

from lxml.etree import Element, QName, SubElement, fromstring

from cz_nia.exceptions import NiaException


class NiaMessage(ABC):
    """Base class for messages."""

    govtalk_namespace = 'http://www.govtalk.gov.uk/CM/envelope'

    @property
    @abstractmethod
    def request_namespace(self):
        """Namespace of the request."""

    @property
    @abstractmethod
    def response_namespace(self):
        """Namespace of the response."""

    @property
    @abstractmethod
    def response_class(self):
        """Class of the response."""

    @property
    @abstractmethod
    def action(self):
        """Perfom required action."""

    def __init__(self, data):
        """Store the data we want to pack."""
        self.data = data

    @abstractmethod
    def pack(self) -> Element:
        """Pack the message containing data."""

    @abstractmethod
    def extract_message(self, message: Element) -> str:
        """Extract relevant data from the message."""

    @property
    def get_namespace_map(self) -> Dict[str, str]:
        """Return namespace map for the message."""
        return {'gov': self.govtalk_namespace, 'nia': self.response_namespace}

    def unpack(self, response: bytes) -> str:
        """Unpack the data from the response."""
        parsed_message = self.verify_message(response)
        return self.extract_message(parsed_message)

    def verify_message(self, message: bytes) -> str:
        """Verify the status of the message.

        Raises NiaException if the status is not OK.
        """
        body = fromstring(message)
        nsmap = self.get_namespace_map
        response = body.find('gov:Body/nia:{}'.format(self.response_class), namespaces=nsmap)
        if response.find('nia:Status', namespaces=nsmap).text != 'OK':
            raise NiaException(response.find('nia:Detail', namespaces=nsmap).text)
        return response


class IdentificationMessage(NiaMessage):
    """Message for TR_ZTOTOZNENI."""

    request_namespace = 'urn:nia.ztotozneni/request:v3'
    response_namespace = 'urn:nia.ztotozneni/response:v4'
    response_class = 'ZtotozneniResponse'
    action = 'TR_ZTOTOZNENI'

    def pack(self) -> Element:
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

    def extract_message(self, response: Element) -> str:
        """Get pseudonym from the message."""
        return response.find('nia:Pseudonym', namespaces=self.get_namespace_map).text
