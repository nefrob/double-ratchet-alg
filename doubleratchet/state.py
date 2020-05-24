from __future__ import absolute_import

# FIXME: remove dependence on pickle (needed for serializing 
# passed interface implementation classes)
import pickle

from .interfaces.serializable import SerializableIface


# State for a party in double-ratchet algorithm
class State(SerializableIface):
  def __init__(self, keypair, public_key, keystorage, 
      root_chain, symmetric_chain):
    self._dh_pair = None
    self._dh_pk_r = None

    self._root = None
    self._send = None 
    self._receive = None
    self._prev_send_len = 0

    self._hk_s = None
    self._hk_r = None
    self._next_hk_s = None
    self._next_hk_r = None
    
    self._delayed_send_ratchet = False

    self._skipped_mks = None
    self._skipped_count = 0

    self._keypair = keypair
    self._public_key = public_key
    self._keystorage = keystorage
    self._root_chain = root_chain
    self._symmetric_chain = symmetric_chain

  # Sets initial sender state
  def init_sender(self, sk, dh_pk_r):
    self._dh_pair = self._keypair.generate_dh()
    self._dh_pk_r = dh_pk_r

    self._root = self._root_chain()
    self._root.ck = sk
    self._send = self._symmetric_chain()
    self._receive = self._symmetric_chain()
    self._prev_send_len = 0

    self._delayed_send_ratchet = True

    self._skipped_mks = self._keystorage()
    self._skipped_count = 0

  # Sets initial sender state (header encryption variant)
  def init_sender_he(self, sk, dh_pk_r, hk_s, next_hk_r):
    self._dh_pair = self._keypair.generate_dh()
    self._dh_pk_r = dh_pk_r

    self._root = self._root_chain()
    self._root.ck = sk
    self._send = self._symmetric_chain()
    self._receive = self._symmetric_chain()
    self._prev_send_len = 0

    self._hk_s = hk_s
    self._hk_r = None
    self._next_hk_s = None
    self._next_hk_r = next_hk_r

    self._delayed_send_ratchet = True

    self._skipped_mks = self._keystorage()
    self._skipped_count = 0

  # Sets initial receiver state
  def init_receiver(self, sk, dh_pair):
    self._dh_pair = dh_pair
    self._dh_pk_r = None

    self._root = self._root_chain()
    self._root.ck = sk
    self._send = self._symmetric_chain()
    self._receive = self._symmetric_chain()
    self._prev_send_len = 0

    self._delayed_send_ratchet = False

    self._skipped_mks = self._keystorage()
    self._skipped_count = 0

  # Sets initial receiver state (header encryption variant)
  def init_receiver_he(self, sk, dh_pair, next_hk_s, next_hk_r):
    self._dh_pair = dh_pair
    self._dh_pk_r = None

    self._root = self._root_chain()
    self._root.ck = sk
    self._send = self._symmetric_chain()
    self._receive = self._symmetric_chain()
    self._prev_send_len = 0

    self._hk_s = None
    self._hk_r = None
    self._next_hk_s = next_hk_s
    self._next_hk_r = next_hk_r

    self._delayed_send_ratchet = False

    self._skipped_mks = self._keystorage()
    self._skipped_count = 0

  # Getter/setters

  @property
  def dh_pair(self):
    return self._dh_pair
  
  @dh_pair.setter
  def dh_pair(self, val):
    self._dh_pair = val
  
  @property
  def dh_pk_r(self):
    return self._dh_pk_r
  
  @dh_pk_r.setter
  def dh_pk_r(self, val):
    self._dh_pk_r = val

  @property
  def root(self):
    return self._root

  @property
  def send(self):
    return self._send
  
  @property
  def receive(self):
    return self._receive

  @property
  def prev_send_len(self):
    return self._prev_send_len
  
  @prev_send_len.setter
  def prev_send_len(self, val):
    self._prev_send_len = val

  @property
  def hk_s(self):
    return self._hk_s
  
  @hk_s.setter
  def hk_s(self, val):
    self._hk_s = val

  @property
  def hk_r(self):
    return self._hk_r
  
  @hk_r.setter
  def hk_r(self, val):
    self._hk_r = val

  @property
  def next_hk_s(self):
    return self._next_hk_s
  
  @next_hk_s.setter
  def next_hk_s(self, val):
    self._next_hk_s = val

  @property
  def next_hk_r(self):
    return self._next_hk_r
  
  @next_hk_r.setter
  def next_hk_r(self, val):
    self._next_hk_r = val

  @property
  def delayed_send_ratchet(self):
    return self._delayed_send_ratchet

  @delayed_send_ratchet.setter
  def delayed_send_ratchet(self, val):
    self._delayed_send_ratchet = val

  @property
  def skipped_mks(self):
    return self._skipped_mks

  @property
  def skipped_count(self):
    return self._skipped_count

  @skipped_count.setter
  def skipped_count(self, val):
    self._skipped_count = val

  # Serialize class
  def serialize(self):
    return {
      "dh_pair" : self._dh_pair.serialize(),
      "dh_pk_r": self._dh_pk_r.serialize(),
      "root": self._root.serialize(),
      "send": self._send.serialize(),
      "receive": self._receive.serialize(),
      "prev_send_len": self._prev_send_len,
      "hk_s": self._hk_s,
      "hk_r": self._hk_r,
      "next_hk_s": self._next_hk_s,
      "next_hk_r": self._next_hk_r,
      "delayed_send_ratchet": self._delayed_send_ratchet,
      "skipped_mks": self._skipped_mks.serialize(),
      "skipped_count": self._skipped_count,
      "keypair_class": pickle.dumps(self._keypair),
      "pk_class": pickle.dumps(self._public_key),
      "keystorage_class": pickle.dumps(self._keystorage),
      "root_chain_class": pickle.dumps(self._root_chain),
      "symmetric_chain_class": pickle.dumps(self._symmetric_chain)
    }
  
  # Deserialize class
  @classmethod
  def deserialize(cls, serialized_dict):
    if not isinstance(serialized_dict, dict):
      raise TypeError("serialized_dict must be of type: dict")

    keypair_class = pickle.loads(serialized_dict["keypair_class"])
    pk_class = pickle.loads(serialized_dict["pk_class"])
    keystorage_class = pickle.loads(serialized_dict["keystorage_class"])
    root_chain_class = pickle.loads(serialized_dict["root_chain_class"])
    symmetric_chain_class = pickle.loads(serialized_dict["symmetric_chain_class"])

    state = cls(keypair_class, pk_class, keystorage_class, root_chain_class,
      symmetric_chain_class)

    state._dh_pair = keypair_class.deserialize(serialized_dict["dh_pair"])
    state._dh_pk_r = pk_class.deserialize(serialized_dict["dh_pk_r"])
    state._root = root_chain_class.deserialize(serialized_dict["root"])
    state._send = symmetric_chain_class.deserialize(serialized_dict["send"])
    state._receive = symmetric_chain_class.deserialize(serialized_dict["receive"])
    state._prev_send_len = serialized_dict["prev_send_len"]
    state._hk_s = serialized_dict["hk_s"]
    state._hk_r = serialized_dict["hk_r"]
    state._next_hk_s = serialized_dict["next_hk_s"]
    state._next_hk_r = serialized_dict["next_hk_r"]
    state._delayed_send_ratchet = serialized_dict["delayed_send_ratchet"]
    state._skipped_mks = keystorage_class.deserialize(serialized_dict["skipped_mks"])
    state._skipped_count = serialized_dict["skipped_count"]

    return state
