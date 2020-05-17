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
    self.hk_s = None
    self.hk_r = None
    self.next_hk_s = None
    self.next_hk_r = None
    self.send_msg_no = 0
    self.recv_msg_no = 0
    self.prev_chain_len = 0
    self.skipped_mks = None
    self.skipped_lifetimes = []


# Header for ratchet chain message.
class MsgHeader:
  def __init__(self, pk, prev_chain_len, msg_no):
    assert(isinstance(pk, X448PublicKey))

    self.pk = pk
    self.prev_chain_len = prev_chain_len
    self.msg_no = msg_no

  def __bytes__(self):
    key_bytes = pk_to_bytes(self.pk)
    return key_bytes + self.prev_chain_len.to_bytes(2, byteorder='little') \
      + self.msg_no.to_bytes(2, byteorder='little')

  def __str__(self):
    key_str = str(pk_to_bytes(self.pk))[2:-1] # skip starting "b'" and ending "'"
    return key_str + "," + str(self.prev_chain_len) + "," + str(self.msg_no)
  
