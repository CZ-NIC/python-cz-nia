"""Testing utilities."""
from lxml import etree


def load_xml(xml):
    """Load and parse XML string to Etree object."""
    parser = etree.XMLParser(remove_blank_text=True, remove_comments=True,
                             resolve_entities=False)
    return etree.fromstring(xml.strip(), parser=parser)
