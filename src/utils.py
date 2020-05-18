from sys import getsizeof

from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

from .crypto import X448_KEY_BYTES
from .state import MsgHeader
from json import loads

# Return new message header.
def build_header(dh_pair, prev_chain_len, msg_no):
  assert(isinstance(dh_pair, X448PrivateKey))

  return MsgHeader(
    dh_pair.public_key(), 
    prev_chain_len, 
    msg_no)

# Return header from bytes array.
def header_from_bytes(hdr_bytes):
  if hdr_bytes == None:
    return None

  assert(isinstance(hdr_bytes, bytes))

  pk = X448PublicKey.from_public_bytes(hdr_bytes[:X448_KEY_BYTES])
  prev_chain_len = int.from_bytes(hdr_bytes[-4:-2], byteorder='little')
  msg_no = int.from_bytes(hdr_bytes[-2:], byteorder='little')
  return MsgHeader(pk, prev_chain_len, msg_no)

# Restore old state to state object.
# FIXME: we cannot simply assign or it will change ref'd state obj.
# Alternatively we could return new state (i.e. old_state) but this
# will require reconstruction in decrypt ...
def restore_decrypt_state(state, old_state):
  state.dh_pair = old_state.dh_pair
  state.peer_pk = old_state.peer_pk
  state.rk = old_state.rk
  state.ck_s = old_state.ck_s
  state.ck_r = old_state.ck_r
  state.hk_s = old_state.hk_s
  state.hk_r = old_state.hk_r
  state.next_hk_s = old_state.next_hk_s
  state.next_hk_r = old_state.next_hk_r
  state.delayed_send_ratchet = old_state.delayed_send_ratchet
  state.send_msg_no = old_state.send_msg_no
  state.recv_msg_no = old_state.recv_msg_no
  state.prev_chain_len = old_state.prev_chain_len
  state.skipped_mks = old_state.skipped_mks
  state.skipped_lifetimes = old_state.skipped_lifetimes