from abc import ABC, abstractmethod


class MsgKeyStorageIface(ABC):
  """TODO:"""

  @abstractmethod
  def lookup(self, key):
    """TODO:"""
    pass

  @abstractmethod
  def put(self, key, value):
    """TODO:"""
    pass

  @abstractmethod
  def delete(self, key):
    """TODO:"""
    pass

  @abstractmethod
  def size(self):
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
