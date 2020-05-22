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

  @abstractmethod
  def dh_out(self, dh_pk):
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

  @abstractmethod
  def is_equal_to(self, dh_pk):
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
