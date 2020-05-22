from __future__ import absolute_import

from abc import abstractmethod

from .serializable import SerializableIface

class MsgKeyStorageIface(SerializableIface):
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
  def count(self):
    """TODO:"""
    pass

  @abstractmethod
  def items(self):
    """TODO:"""
    pass

  @abstractmethod
  def notify_event(self):
    """TODO:"""
    pass
