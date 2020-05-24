from __future__ import absolute_import

from abc import abstractmethod

from .serializable import SerializableIface

class MsgKeyStorageIface(SerializableIface):
  """Dictionary-like Message Key Storage Interface"""

  @abstractmethod
  def front(self):
    """Returns first (oldest) stored message key."""
    pass

  @abstractmethod
  def lookup(self, key):
    """Returns value for provided key, None if key is not present."""
    pass

  @abstractmethod
  def put(self, key, value):
    """Puts key-value pair in datastructure."""
    pass

  @abstractmethod
  def delete(self, key):
    """Deletes current key and associated value from datastructure."""
    pass

  @abstractmethod
  def count(self):
    """Returns number of message keys stored."""
    pass

  @abstractmethod
  def items(self):
    """Returns list of all (key, value) tuples."""
    pass

  @abstractmethod
  def notify_event(self):
    """Performs storage updates (ex. key deletion) due to Double Ratchet
    event (ex. successful decryption)."""
    pass
