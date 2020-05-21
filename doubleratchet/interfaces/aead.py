from abc import ABC, abstractmethod


class AEADIFace(ABC):
  """TODO:"""

  @staticmethod
  @abstractmethod
  def encrypt(pt, associated_data = None):
    """TODO:"""
    pass

  @staticmethod
  @abstractmethod
  def decrypt(ct, associated_data = None):
    """TODO:"""
    pass
