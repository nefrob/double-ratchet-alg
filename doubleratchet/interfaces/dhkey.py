from __future__ import absolute_import

from abc import abstractmethod

from .serializable import SerializableIface


class DHKeyPairIface(SerializableIface):
  """TODO:"""

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


class DHPublicKeyIface(SerializableIface):
  """TODO:"""

  @abstractmethod
  def pk_bytes(self):
    """TODO:"""
    pass

  @classmethod
  @abstractmethod
  def from_bytes(cls, pk_bytes):
    """TODO:"""
    pass

  @property
  @abstractmethod
  def public_key(self):
    """TODO:"""
    pass
