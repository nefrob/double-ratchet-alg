from __future__ import absolute_import

from abc import ABC, abstractmethod


class RatchetIface(ABC):
  """Double Ratchet Algorithm Communication Interface"""

  @staticmethod
  @abstractmethod
  def encrypt_message(state, pt, associated_data, aead):
    """Encrypts plaintext from provided state using Double Ratchet algorithm."""
    pass

  @staticmethod
  @abstractmethod
  def decrypt_message(state, msg, associated_data, aead, keypair):
    """Decrypts message ciphertext as provided state using Double 
    Ratchet algorithm."""
    pass
