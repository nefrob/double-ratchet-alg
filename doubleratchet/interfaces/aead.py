from __future__ import absolute_import

from abc import ABC, abstractmethod


class AEADIFace(ABC):
  """Authenticated Encryption with Associated Data Interface"""

  @staticmethod
  @abstractmethod
  def encrypt(key, pt, associated_data = None):
    """Encrypts plaintext, with associated data authentication, using
      provided key with an AEAD scheme.
    """
    pass

  @staticmethod
  @abstractmethod
  def decrypt(key, ct, associated_data = None):
    """Decrypts ciphertext and authenticates associated data using
      provided key with an AEAD scheme.
    """
    pass
