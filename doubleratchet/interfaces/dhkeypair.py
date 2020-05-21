from abc import ABC, abstractmethod


class DHKeyPairIface(ABC):
  """TODO:"""

  @abstractmethod
  def __init__(self):
    pass

  @classmethod
  @abstractmethod
  def generate_dh(cls):
    """TODO:"""
    pass

  @staticmethod
  @abstractmethod
  def dh_out(priv_a, pub_b):
    """TODO:"""
    pass

  @abstractmethod
  def serialize(self):
    """TODO:"""
    pass
  
  @classmethod
  @abstractmethod
  def deserialize(cls):
    """TODO:"""
    pass

  @property
  @abstractmethod
  def private_key(self):
    """TODO:"""
    pass

  @property
  @abstractmethod
  def public_key(self):
    """TODO:"""  
    pass
