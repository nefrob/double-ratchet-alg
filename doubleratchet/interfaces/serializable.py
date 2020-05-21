from abc import ABC, abstractmethod


class SerializableIface(ABC):
  """TODO:"""

  @abstractmethod
  def serialize(self):
    """TODO:"""
    pass

  @classmethod
  @abstractmethod
  def deserialize(cls, serialized_obj):
    """TODO:"""
    pass
