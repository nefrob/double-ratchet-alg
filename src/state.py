from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey

from .crypto_utils import pk_to_bytes


# State for a party in double-ratchet algorithm.
class RatchetState:
  def __init__(self):
    self.dh_pair = None
    self.peer_pk = None
    self.rk = None
    self.ck_s = None 
    self.ck_r = None
    self.send_msg_no = 0
    self.recv_msg_no = 0
    self.prev_chain_len = 0
    self.skipped_mks = {}


# Header for ratchet chain message.
class MsgHeader:
  def __init__(self, pk, prev_chain_len, msg_no):
    assert(isinstance(pk, X448PublicKey))

    self.pk = pk
    self.prev_chain_len = prev_chain_len
    self.msg_no = msg_no

  def to_bytes(self):
    key_bytes = pk_to_bytes(self.pk)
    counters = (str(self.prev_chain_len) + str(self.msg_no)).encode("utf-8")
    return key_bytes + counters
