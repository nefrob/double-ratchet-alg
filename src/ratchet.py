'''
Double Ratchet Algorithm
Ref: https://signal.org/docs/specifications/doubleratchet/
'''

from copy import copy
import src.utils as utils
import src.crypto_utils as crypto_utils
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

# Max number of message keys that can be skipped in a single chain
MAX_SKIP = 1000


'''
Sets initial sender state. Receiving chain key can be initialized 
with shared secret so that peer can send messages immediately after
initialization.
'''
def init_sender(state, sk, peer_pk, ck_r = None):
  assert(isinstance(state, utils.State))
  assert(isinstance(sk, bytes))
  assert(isinstance(peer_pk, X448PublicKey))

  state.dh_pair = crypto_utils.gen_dh_keys()
  state.peer_pk = peer_pk
  state.rk, state.ck_s = crypto_utils.ratchet_root(
    crypto_utils.get_dh_out(state.dh_pair, peer_pk), sk)
  state.ck_r = ck_r
  state.send_msg_no = 0
  state.recv_msg_no = 0
  state.prev_chain_len = 0
  state.skipped_mks = {}


'''
Sets initial receiver state. Sending chain key can be initialized 
with  shared secret so messages can be sent immediately after
initialization.
'''
def init_receiver(state, sk, dh_pair, ck_s = None):
  assert(isinstance(state, utils.State))
  assert(isinstance(sk, bytes))
  assert(isinstance(dh_pair, X448PrivateKey))

  state.dh_pair = dh_pair
  state.peer_pk = None
  state.rk = sk
  state.ck_s = ck_s
  state.ck_r = None
  state.send_msg_no = 0
  state.recv_msg_no = 0
  state.prev_chain_len = 0
  state.skipped_mks = {}


'''
Encrypts a message to be sent, ratcheting the sending chain.

Note: On exception (ex. message encryption failure), the message is
discarded as well as any state changes made.
'''
def encrypt_msg(state, pt, associated_data):
  assert(isinstance(state, utils.State))
  assert(isinstance(pt, str))
  assert(isinstance(associated_data, bytes))

  old_ck = state.ck_s
  old_msg_no = state.send_msg_no

  state.ck_s, mk = crypto_utils.ratchet_chain(state.ck_s)
  header = utils.build_header(state.dh_pair, 
    state.prev_chain_len, state.send_msg_no)
  state.send_msg_no += 1

  ct, ret = crypto_utils.encrypt(mk, pt, 
    utils.encode_header(associated_data, header))

  if ret != crypto_utils.CRYPTO_RET.SUCCESS:
    # Restore state
    state.ck_r = old_ck
    state.send_msg_no = old_msg_no
    return None, None
  
  return header, ct


'''
Decrypts a message. If message was skipped then uses skipped message map
to decrypt message. If new peer DH key is received, any skipped message keys
on the current chain are stored (from ratchets) and a DH-ratchet step is
performed. Skipped message keys on the new chain are then also stored (from
ratchets). The message is then decrypted.

Note: On exception (ex. message authentication failure), the message is
discarded as well as any state changes made.
'''
def decrypt_msg(state, header, ct, associated_data):
  assert(isinstance(state, utils.State))
  assert(isinstance(header, utils.MsgHeader))
  assert(isinstance(ct, bytes))
  assert(isinstance(associated_data, bytes))

  pt = try_skipped_mks(state, header, ct, associated_data)
  if pt != None:
    return pt
  
  old_state = copy(state)

  if not crypto_utils.pks_equal(header.pk, state.peer_pk): # save mks from old recv chain
    try:
      skip_over_mks(state, header.prev_chain_len)
    except:
      restore_decrypt_state(state, old_state)
      return None
    
    dh_ratchet(state, header.pk)
  
  try:
    skip_over_mks(state, header.msg_no) # save mks on new sending chain
  except:
    restore_decrypt_state(state, old_state)
    return None

  state.ck_r, mk = crypto_utils.ratchet_chain(state.ck_r)
  state.recv_msg_no += 1

  pt, ret = crypto_utils.decrypt(
    mk, ct, utils.encode_header(associated_data, header))
  if ret != crypto_utils.CRYPTO_RET.SUCCESS:
    restore_decrypt_state(state, old_state)
    return None

  return pt


'''
Restore old state to state object.

FIXME: we cannot simply assign or it will change ref'd state obj.
Alternatively we could return new state (i.e. old_state) but this
will require reconstruction in decrypt ...
'''
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


'''
Returns plain text if the message corresponds to a skipped message key,
deleting the key from the saved key map.
'''
def try_skipped_mks(state, header, ct, associated_data):
  hdr_pk_bytes = crypto_utils.pk_bytes(header.pk)

  if (hdr_pk_bytes, header.msg_no) in state.skipped_mks:
    mk = state.skipped_mks[(hdr_pk_bytes, header.msg_no)]
    del state.skipped_mks[(hdr_pk_bytes, header.msg_no)]

    pt, ret = crypto_utils.decrypt(
      mk, ct, utils.encode_header(associated_data, header))
    if ret == crypto_utils.CRYPTO_RET.SUCCESS:
      return pt

  return None


'''
If new ratchet key received then store skipped message keys 
from receiving chain and ratchet receiving chain.
'''
def skip_over_mks(state, end_msg_no):
  if state.recv_msg_no + MAX_SKIP < end_msg_no:
    raise "Error: invalid end message number."
  elif state.ck_r != None:
    while state.recv_msg_no < end_msg_no:
      state.ck_r, mk = crypto_utils.ratchet_chain(state.ck_r)
      state.skipped_mks[(crypto_utils.pk_bytes(state.peer_pk), state.recv_msg_no)] = mk
      state.recv_msg_no += 1


'''
Performs DH-ratchet step, updating the root chain twice and
so resetting sending/receiving chains.
'''
def dh_ratchet(state, peer_pk):
  state.peer_pk = peer_pk
  state.rk, state.ck_r = crypto_utils.ratchet_root(
    crypto_utils.get_dh_out(state.dh_pair, state.peer_pk), state.rk)
  state.dh_pair = crypto_utils.gen_dh_keys()
  state.rk, state.ck_s = crypto_utils.ratchet_root(
    crypto_utils.get_dh_out(state.dh_pair, state.peer_pk), state.rk)
  state.prev_chain_len = state.send_msg_no
  state.send_msg_no = 0
  state.recv_msg_no = 0
