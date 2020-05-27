"""CZ_NIA application settings wrapper."""


class CzNiaAppSettings(object):
    """CZ_NIA specific settings."""

    def __init__(self, settings):
        """Instantiate settings object from a settings dictionary.

        Raises KeyError if required setting is not provided.
        """
        # FIXME: The explicit cast to `str` on file based settings must remain for as long as we support Python 3.5
        #        since it cannot correctly handle PosixPath getting here
        # Settings for transport
        self.TRANSPORT_TIMEOUT = settings.get('transport_timeout', 10)
        self.CACHE_TIMEOUT = settings.get('cache_timeout', 3600)
        self.CACHE_PATH = str(settings['cache_path']) if settings.get('cache_path') else None
        # Authentication settings
        self.CERTIFICATE = str(settings['certificate'])
        self.KEY = str(settings['key'])
        self.PASSWORD = settings['password']
        # WSDL files
        self.IDENTITY_WSDL = str(settings['identity_wsdl'])
        self.FEDERATION_WSDL = str(settings['federation_wsdl'])
        self.PUBLIC_WSDL = str(settings['public_wsdl'])
        # Endpoint adresses
        self.FEDERATION_ADDRESS = settings['federation_address']
        self.PUBLIC_ADDRESS = settings['public_address']
        # Debug
        self.DEBUG = settings.get('debug', False)
