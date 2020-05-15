'''
Utility functions.
'''

from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey


'''
State for sender/receiver in double-ratchet algorithm.
'''
class State:
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


'''
Header for ratchet chain message.
'''
class MsgHeader:
  def __init__(self, pk, prev_chain_len, msg_no):
    assert(isinstance(pk, X448PublicKey))

    self.pk = pk
    self.prev_chain_len = prev_chain_len
    self.msg_no = msg_no


'''
Return new message header.
'''
def build_header(dh_pair, prev_chain_len, msg_no):
  assert(isinstance(dh_pair, X448PrivateKey))

  return MsgHeader(
    dh_pair.public_key(), 
    prev_chain_len, 
    msg_no
  )


'''
Returns associated data and message header as parseable 
byte sequence. 
'''
def encode_header(associated_data, header):
  assert(isinstance(associated_data, bytes))
  assert(isinstance(header, MsgHeader))

  return associated_data + repr(header).encode('utf-8')
