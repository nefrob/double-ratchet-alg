from __future__ import absolute_import

from abc import abstractmethod

from .serializable import SerializableIface


class KDFChainIface(SerializableIface):
  """TODO:"""

  @ck.setter
  @abstractmethod
  def ck(self, val):
    """TODO:"""
    pass

class SymmetricChainIface(KDFChainIface):
  """TODO:"""

  @abstractmethod
  def ratchet(self):
    """TODO:"""
    pass

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

class RootChainIface(KDFChainIface):
  """TODO:"""

  @abstractmethod
  def ratchet(self, dh_out):
    """TODO:"""
    pass
