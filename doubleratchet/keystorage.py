from __future__ import absolute_import

from collections import OrderedDict

from .interfaces.keystorage import MsgKeyStorageIface


class MsgKeyStorage(MsgKeyStorageIface):
  def __init__(self, skipped_mks = None):
    if skipped_mks:
      if not isinstance(skipped_mks, OrderedDict):
        raise TypeError("skipped_mks must be of type: OrderedDict")

      self._skipped_mks = skipped_mks
    else:
      self._skipped_mks = OrderedDict()

  def front(self):
    return next(iter(self._skipped_mks))

  def lookup(self, key):
    if key not in self._skipped_mks:
      return None
    return self._skipped_mks[key]

  def put(self, key, value):
    self._skipped_mks[key] = value

  def delete(self, key):
    del self._skipped_mks[key]

  def count(self):
    return len(self._skipped_mks)

  def items(self):
    return self._skipped_mks.items()

  def notify_event(self):
    pass # TODO: handle decrypt event delete keys

  def serialize(self):
    return dict(self._skipped_mks)
  
  @classmethod
  def deserialize(cls, serialized_dict):
    return cls(OrderedDict(serialized_dict))