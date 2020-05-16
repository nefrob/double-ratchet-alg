from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey

from .state import MsgHeader


# Return new message header.
def build_header(dh_pair, prev_chain_len, msg_no):
  assert(isinstance(dh_pair, X448PrivateKey))

  return MsgHeader(
    dh_pair.public_key(), 
    prev_chain_len, 
    msg_no)


# Return associated data and message header as byte sequence.
def encode_header(associated_data, header):
  assert(isinstance(associated_data, bytes))
  assert(isinstance(header, MsgHeader))

  return associated_data + header.to_bytes()

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
  state.send_msg_no = old_state.send_msg_no
  state.recv_msg_no = old_state.recv_msg_no
  state.prev_chain_len = old_state.prev_chain_len
  state.skipped_mks = old_state.skipped_mks