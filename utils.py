'''
Utility functions.
'''

from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey


'''
Header for ratchet chain message.
'''
class MsgHeader:
  def __init__(self, pk, prev_chain_len, msg_no):
    self.pk = pk
    self.prev_chain_len = prev_chain_len
    self.msg_no = msg_no

'''
Return new message header.
'''
def build_header(dh_pair, prev_chain_len, msg_no):
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
  return associated_data + bytes(header)
