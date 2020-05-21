from abc import ABC, abstractmethod


class KDFChainIface(ABC):
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
  def deserialize(cls):
    """TODO:"""
    pass
