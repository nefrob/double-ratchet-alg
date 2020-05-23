from __future__ import absolute_import

from collections import OrderedDict

from .interfaces.keystorage import MsgKeyStorageIface


class MsgKeyStorage(MsgKeyStorageIface):
  EVENT_THRESH = 5 # a key is deleted when event count reaches threshold

  def __init__(self, skipped_mks = None, event_count = 0):
    if skipped_mks:
      if not isinstance(skipped_mks, OrderedDict):
        raise TypeError("skipped_mks must be of type: OrderedDict")

      self._skipped_mks = skipped_mks
    else:
      self._skipped_mks = OrderedDict()

    if not isinstance(event_count, int):
      raise TypeError("event_count must be of type: int")
    if event_count < 0:
      raise ValueError("event_count must be positive")
    self._event_count = event_count

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
    if len(self._skipped_mks) == 0:
      self._event_count = 0
      return

    self._event_count = (self._event_count + 1) % MsgKeyStorage.EVENT_THRESH
    if self._event_count == 0:
      del self._skipped_mks[self.front()]

  def serialize(self):
    return {
      "skipped_mks": dict(self._skipped_mks),
      "event_count": self._event_count
    }
  
  @classmethod
  def deserialize(cls, serialized_dict):
    return cls(
      OrderedDict(serialized_dict["skipped_mks"]),
      serialized_dict["event_count"]
    )
