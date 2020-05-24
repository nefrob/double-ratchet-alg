from __future__ import absolute_import

from abc import ABC, abstractmethod


class SerializableIface(ABC):
  """Serializable Interface"""

  @abstractmethod
  def serialize(self):
    """Returns serialized dict of class state."""
    pass

  @classmethod
  @abstractmethod
  def deserialize(cls, serialized_obj):
    """Class instance from serialized class state."""
    pass
