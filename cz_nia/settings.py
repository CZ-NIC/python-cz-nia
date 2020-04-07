"""CZ_NIA application settings wrapper."""


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
        self.IDENTITY_WSDL = settings['identity_wsdl']
        self.FEDERATION_WSDL = settings['federation_wsdl']
        self.PUBLIC_WSDL = settings['public_wsdl']
        # Endpoint adresses
        self.FEDERATION_ADDRESS = settings['federation_address']
        self.PUBLIC_ADDRESS = settings['public_address']
        # Debug
        self.DEBUG = settings.get('debug', False)
