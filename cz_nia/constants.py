"""Constants for NIA communications."""
from enum import Enum, unique


@unique
class AuthenticatorStatus(str, Enum):
    """Enum for status of Authenticator."""

    ACTIVE = "Aktivni"
    INACTIVE = "Neaktivni"
    TERMINATED = "Ukonceny"


@unique
class AuthenticationLevel(str, Enum):
    """Enum for LoA types."""

    LOW = "Low"
    SUBSTANTIAL = "Substantial"
    HIGH = "High"


@unique
class IdCardType(str, Enum):
    """Enum for ID card types."""

    IDENTITY_CARD = "ID"
    PASSPORT = "P"
    VISA = "VS"
    STAY_PERMIT = "IR"
    STAY_CARD = "PS"
