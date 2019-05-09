"""Module with WSSE extensions."""
from .signature import BinarySignature, MemorySignature, SAMLTokenSignature, Signature

__all__ = ['BinarySignature', 'MemorySignature', 'SAMLTokenSignature', 'Signature']
