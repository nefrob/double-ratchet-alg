from __future__ import absolute_import

from abc import ABC, abstractmethod


class RatchetIface(ABC):
  """TODO:"""

  @staticmethod
  @abstractmethod
  def encrypt_message(state, pt, associated_data, aead):
    """TODO:"""
    pass

  @staticmethod
  @abstractmethod
  def decrypt_message(state, msg, associated_data, aead):
    """TODO:"""
    pass
