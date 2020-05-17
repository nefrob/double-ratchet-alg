'''
Double Ratchet Algorithm
Ref: https://signal.org/docs/specifications/doubleratchet/
'''

from copy import copy

from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

from .crypto import *
from .crypto_utils import pks_equal, pk_to_bytes
from .state import RatchetState, MsgHeader
from .utils import build_header, header_from_bytes, restore_decrypt_state

MAX_SKIP = 1000 # max message keys skipped in single chain
DELETE_EVENT_NUM = 5 # events before an old skipped mk is deleted


# FIXME: let caller choose crypto algs/sizes
def init_sender(state, sk, peer_pk, hk_s, next_hk_r):
  """Sets initial sender state.
  """
  assert(isinstance(state, RatchetState))
  assert(isinstance(sk, bytes))
  assert(isinstance(peer_pk, X448PublicKey))

  state.dh_pair = gen_dh_keys()
  state.peer_pk = peer_pk
  state.rk, state.ck_s, state.next_hk_s = ratchet_root(
    get_dh_out(state.dh_pair, peer_pk), sk)
  state.ck_r = None
  state.hk_s = hk_s
  state.hk_r = None
  state.next_hk_r = next_hk_r
  state.send_msg_no = 0
  state.recv_msg_no = 0
  state.prev_chain_len = 0
  state.skipped_mks = {}
  state.event_counter = 0 

# FIXME: let caller choose crypto algs/sizes
def init_receiver(state, sk, dh_pair, next_hk_s, next_hk_r):
  """Sets initial receiver state.
  """
  assert(isinstance(state, RatchetState))
  assert(isinstance(sk, bytes))
  assert(isinstance(dh_pair, X448PrivateKey))

  state.dh_pair = dh_pair
  state.peer_pk = None
  state.rk = sk
  state.ck_s = None
  state.ck_r = None
  state.hk_s = None
  state.hk_r = None
  state.next_hk_s = next_hk_s
  state.next_hk_r = next_hk_r
  state.send_msg_no = 0
  state.recv_msg_no = 0
  state.prev_chain_len = 0
  state.skipped_mks = {}
  state.event_counter = 0 

def encrypt_msg(state, pt, associated_data, ):
  """Returns encrypted header and ciphertext for encrypted message.

  On header or message encryption failure the message is discarded
  and state reverted (ciphertext is None).
  """
  assert(isinstance(state, RatchetState))
  assert(isinstance(pt, str))
  assert(isinstance(associated_data, bytes))

  old_ck = state.ck_s
  old_msg_no = state.send_msg_no

  state.ck_s, mk = ratchet_chain(state.ck_s)
  header = build_header(state.dh_pair, 
    state.prev_chain_len, state.send_msg_no)
  # FIXME: header needs AAD
  hdr_ct, ret = encrypt_gcm(state.hk_s, bytes(header), None)

  if ret != CRYPTO_RET.SUCCESS: # restore state on fail
    state.ck_r = old_ck 
    state.send_msg_no = old_msg_no
    return None, None

  state.send_msg_no += 1

  ct, ret = encrypt_gcm(mk, pt.encode("utf-8"), associated_data + hdr_ct)
  if ret != CRYPTO_RET.SUCCESS: # restore state on fail
    state.ck_r = old_ck
    state.send_msg_no = old_msg_no
    return None, None
  
  return hdr_ct, ct

def decrypt_msg(state, hdr_ct, ct, associated_data):
  """Returns plaintext message from encrypted ciphertext.

  On header or message decryption failure the message is 
  discarded and state reverted (plaintext is None).
  """
  assert(isinstance(state, RatchetState))
  assert(isinstance(hdr_ct, bytes))
  assert(isinstance(ct, bytes))
  assert(isinstance(associated_data, bytes))

  pt = try_skipped_mks(state, hdr_ct, ct, associated_data)
  if pt != None:
    update_event_counter(state) # successful decrypt event
    delete_old_skipped_mks(state)
    return pt
  
  old_state = copy(state)
  try:
    header, should_dh_ratchet = decrypt_header(state, hdr_ct)
  except:
    restore_decrypt_state(state, old_state)
    return None

  if should_dh_ratchet:
    try:
      skip_over_mks(state, header.prev_chain_len) # save mks from old recv chain
      dh_ratchet(state, header.pk)
    except:
      restore_decrypt_state(state, old_state)
      return None

  try:
    skip_over_mks(state, header.msg_no) # save mks on new sending chain
  except:
    restore_decrypt_state(state, old_state)
    return None

  state.ck_r, mk = ratchet_chain(state.ck_r)
  state.recv_msg_no += 1

  pt_bytes, ret = decrypt_gcm(mk, ct, associated_data + hdr_ct)
  if ret != CRYPTO_RET.SUCCESS:
    restore_decrypt_state(state, old_state)
    return None

  update_event_counter(state) # successful decrypt event
  delete_old_skipped_mks(state)
  
  return pt_bytes.decode("utf-8")

# ----------------------------------------------------------------------------
# Private
# FIXME: make inaccessible, perhaps another interface layer?
# ----------------------------------------------------------------------------


# Returns plain text if the message corresponds to a skipped message key,
# deleting the key from the saved key map.
def try_skipped_mks(state, hdr_ct, ct, associated_data):
  for ((hk_r, msg_no), mk) in state.skipped_mks.items():
    # FIXME: header needs AAD
    hdr_pt_bytes, ret = decrypt_gcm(hk_r, hdr_ct, None)
    header = header_from_bytes(hdr_pt_bytes)
    
    if ret == CRYPTO_RET.SUCCESS and header.msg_no == msg_no:
      del state.skipped_mks[(hk_r, msg_no)]

      pt_bytes, ret = decrypt_gcm(
        mk, ct, associated_data + hdr_ct)
      if ret == CRYPTO_RET.SUCCESS:
        return pt_bytes.decode("utf-8")

  return None

# Returns header and whether ratchet is needed. Tries current and next 
# header receiving keys when decrypting.
# Raises exception on error.
def decrypt_header(state, hdr_ct):
  # FIXME: header needs AAD
  if state.hk_r != None: # may not have ratcheted yet
    hdr_pt_bytes, ret = decrypt_gcm(state.hk_r, hdr_ct, None)
    if ret == CRYPTO_RET.SUCCESS:
      return header_from_bytes(hdr_pt_bytes), False
  # FIXME: header needs AAD
  hdr_pt_bytes, ret = decrypt_gcm(state.next_hk_r, hdr_ct, None)
  if ret == CRYPTO_RET.SUCCESS:
    header = header_from_bytes(hdr_pt_bytes)
    return header, True
  raise Exception("Error: invalid header ciphertext.")

# If new ratchet key received then store skipped message keys 
# from receiving chain and ratchet receiving chain.
# Raises exception on error.
def skip_over_mks(state, end_msg_no):
  if state.recv_msg_no + MAX_SKIP < end_msg_no:
    raise Exception("Error: end message number out of range.")
  elif state.ck_r != None:
    while state.recv_msg_no < end_msg_no:
      state.ck_r, mk = ratchet_chain(state.ck_r)

      if len(state.skipped_mks) == MAX_SKIP: # delete oldest key to make space
        del state.skipped_mks[next(iter(state.skipped_mks))]

      state.skipped_mks[(state.hk_r, state.recv_msg_no)] = mk
      state.recv_msg_no += 1

# Performs DH-ratchet step, updating the root chain twice and
# so resetting sending/receiving chains.
def dh_ratchet(state, peer_pk):
  state.peer_pk = peer_pk
  state.hk_s = state.next_hk_s
  state.hk_r = state.next_hk_r
  state.rk, state.ck_r, state.next_hk_r = ratchet_root(
    get_dh_out(state.dh_pair, state.peer_pk), state.rk)
  state.dh_pair = gen_dh_keys()
  state.rk, state.ck_s, state.next_hk_s = ratchet_root(
    get_dh_out(state.dh_pair, state.peer_pk), state.rk)
  state.prev_chain_len = state.send_msg_no
  state.send_msg_no = 0
  state.recv_msg_no = 0

# Update state event counter. If skipped messages do not exist then
# event counter is reset until 
def update_event_counter(state):
  assert(isinstance(state, RatchetState))

  if len(state.skipped_mks) == 0:
    state.event_counter = 0
  else:
    state.event_counter = (state.event_counter + 1) % DELETE_EVENT_NUM

# Deletes oldest skipped mk after DELETE_EVENT_NUM events.
# Ensures mks aren't stored indefinitely.
def delete_old_skipped_mks(state):
  assert(isinstance(state, RatchetState))

  if len(state.skipped_mks) != 0 and state.event_counter % DELETE_EVENT_NUM == 0:
    del state.skipped_mks[next(iter(state.skipped_mks))]
