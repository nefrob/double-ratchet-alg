from __future__ import absolute_import

from abc import ABC, abstractmethod


class AEADIFace(ABC):
  """TODO:"""

  @staticmethod
  @abstractmethod
  def encrypt(key, pt, associated_data = None):
    """TODO:"""
    pass

  @staticmethod
  @abstractmethod
  def decrypt(key, ct, associated_data = None):
    """TODO:"""
    pass
