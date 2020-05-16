'''
Double Ratchet Algorithm
Ref: https://signal.org/docs/specifications/doubleratchet/
'''

from copy import copy

from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

from .crypto import *
from .crypto_utils import pks_equal, pk_to_bytes
from .state import RatchetState, MsgHeader
from .utils import build_header, encode_header, restore_decrypt_state

# Max number of message keys that can be skipped in a single chain
MAX_SKIP = 1000

# FIXME: let caller choose crypto algs/sizes
def init_sender(state, sk, peer_pk, ck_r = None):
  """Sets initial sender state. 
  
  Receiving chain key can be initialized with a shared secret
  so that receiver can send messages immediately after initialization.
  """
  assert(isinstance(state, RatchetState))
  assert(isinstance(sk, bytes))
  assert(isinstance(peer_pk, X448PublicKey))

  state.dh_pair = gen_dh_keys()
  state.peer_pk = peer_pk
  state.rk, state.ck_s = ratchet_root(
    get_dh_out(state.dh_pair, peer_pk), sk)
  state.ck_r = ck_r
  state.send_msg_no = 0
  state.recv_msg_no = 0
  state.prev_chain_len = 0
  state.skipped_mks = {}

# FIXME: let caller choose crypto algs/sizes
def init_receiver(state, sk, dh_pair, ck_s = None):
  """Sets initial receiver state. 
  
  Sending chain key can be initialized with a shared secret so 
  messages can be sent immediately after initialization.
  """
  assert(isinstance(state, RatchetState))
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

def encrypt_msg(state, pt, associated_data, ):
  """Returns header and ciphertext for encrypted message.

  On message encryption failure the message is discarded and
  state reverted (ciphertext is None).
  """

  assert(isinstance(state, RatchetState))
  assert(isinstance(pt, str))
  assert(isinstance(associated_data, bytes))

  old_ck = state.ck_s
  old_msg_no = state.send_msg_no

  state.ck_s, mk = ratchet_chain(state.ck_s)
  header = build_header(state.dh_pair, 
    state.prev_chain_len, state.send_msg_no)
  state.send_msg_no += 1

  ct, ret = encrypt_gcm(mk, pt, 
    encode_header(associated_data, header))

  if ret != CRYPTO_RET.SUCCESS:
    # Restore state
    state.ck_r = old_ck
    state.send_msg_no = old_msg_no
    return None, None
  
  return header, ct

def decrypt_msg(state, header, ct, associated_data):
  """Returns plaintext message from encrypt ciphertext.

  On message decryption failure the message is discarded and
  state reverted (plaintext is None).
  """

  assert(isinstance(state, RatchetState))
  assert(isinstance(header, MsgHeader))
  assert(isinstance(ct, bytes))
  assert(isinstance(associated_data, bytes))

  pt = try_skipped_mks(state, header, ct, associated_data)
  if pt != None:
    return pt
  
  old_state = copy(state)

  if not pks_equal(header.pk, state.peer_pk): 
    try:
      skip_over_mks(state, header.prev_chain_len) # save mks from old recv chain
    except:
      restore_decrypt_state(state, old_state)
      return None
    
    dh_ratchet(state, header.pk)

  try:
    skip_over_mks(state, header.msg_no) # save mks on new sending chain
  except:
    restore_decrypt_state(state, old_state)
    return None

  state.ck_r, mk = ratchet_chain(state.ck_r)
  state.recv_msg_no += 1

  pt, ret = decrypt_gcm(mk, ct, encode_header(associated_data, header))
  if ret != CRYPTO_RET.SUCCESS:
    restore_decrypt_state(state, old_state)
    return None

  return pt

# ----------------------------------------------------------------------------
# Private
# FIXME: make inaccessible, perhaps another interface layer?
# ----------------------------------------------------------------------------


# Returns plain text if the message corresponds to a skipped message key,
# deleting the key from the saved key map.
def try_skipped_mks(state, header, ct, associated_data):
  hdr_pk_bytes = pk_to_bytes(header.pk)

  if (hdr_pk_bytes, header.msg_no) in state.skipped_mks:
    mk = state.skipped_mks[(hdr_pk_bytes, header.msg_no)]
    del state.skipped_mks[(hdr_pk_bytes, header.msg_no)]

    pt, ret = decrypt_gcm(
      mk, ct, encode_header(associated_data, header))
    if ret == CRYPTO_RET.SUCCESS:
      return pt

  return None

# If new ratchet key received then store skipped message keys 
# from receiving chain and ratchet receiving chain.
def skip_over_mks(state, end_msg_no):
  if state.recv_msg_no + MAX_SKIP < end_msg_no:
    raise "Error: invalid end message number."
  elif state.ck_r != None:
    while state.recv_msg_no < end_msg_no:
      state.ck_r, mk = ratchet_chain(state.ck_r)
      state.skipped_mks[(pk_to_bytes(state.peer_pk), state.recv_msg_no)] = mk
      state.recv_msg_no += 1

# Performs DH-ratchet step, updating the root chain twice and
# so resetting sending/receiving chains.
def dh_ratchet(state, peer_pk):
  state.peer_pk = peer_pk
  state.rk, state.ck_r = ratchet_root(
    get_dh_out(state.dh_pair, state.peer_pk), state.rk)
  state.dh_pair = gen_dh_keys()
  state.rk, state.ck_s = ratchet_root(
    get_dh_out(state.dh_pair, state.peer_pk), state.rk)
  state.prev_chain_len = state.send_msg_no
  state.send_msg_no = 0
  state.recv_msg_no = 0
