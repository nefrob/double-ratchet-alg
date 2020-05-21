from __future__ import absolute_import

from abc import abstractmethod

from .serializable import SerializableIface


class KDFChainIface(SerializableIface):
  """TODO:"""

  @abstractmethod
  def ratchet(self):
    """TODO:"""
    pass

  @abstractmethod
  def serialize(self):
    """TODO:"""
    pass

  @classmethod
  @abstractmethod
  def deserialize(cls, serialized_chain):
    """TODO:"""
    pass


class SymmetricChainIface(KDFChainIface):
  """TODO:"""

  @property
  @abstractmethod
  def msg_no(self):
    """TODO:"""
    pass

  @msg_no.setter
  @abstractmethod
  def msg_no(self, val):
    """TODO:"""
    pass

