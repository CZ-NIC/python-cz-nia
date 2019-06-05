"""CZ_NIA applocation settings wrapper."""


class CzNiaAppSettings(object):
    """CZ_NIA specific settings."""

    def __init__(self, settings):
        """Instantiate settings object from a settings dictionary.

        Raises KeyError if required setting is not provided.
        """
        # Settings for transport
        self.TRANSPORT_TIMEOUT = settings.get('transport_timeout', 10)
        self.CACHE_TIMEOUT = settings.get('cache_timeout', 3600)
        self.CACHE_PATH = settings.get('cache_path', None)
        # Authentication settings
        self.CERTIFICATE = settings['certificate']
        self.KEY = settings['key']
        self.PASSWORD = settings['password']
        # WSDL files
        self.IPSTS_WSDL = settings['ipsts_wsdl']
        self.FPSTS_WSDL = settings['fpsts_wsdl']
        self.PUBLIC_WSDL = settings['public_wsdl']
        # Endpoint adresses
        self.FPSTS_ADDRESS = settings['fpsts_address']
        self.PUBLIC_ADDRESS = settings['public_address']
