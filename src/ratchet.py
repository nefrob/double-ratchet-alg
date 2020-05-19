'''
Double Ratchet Algorithm
Ref: https://signal.org/docs/specifications/doubleratchet/
'''

from copy import copy
from collections import OrderedDict
from src.crypto_utils import dh_pk_bytes

from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey, X448PrivateKey

from .crypto import *
from .crypto_utils import pks_equal
from .state import State, restore_old_state
from .message import Header, Message, MessageHE, header_from_bytes

MAX_SKIP = 1000 # max message keys skipped in single chain
DELETE_MIN_EVENTS = 5 # events before an old skipped mk is deleted


# Sets initial sender state
def init_sender(state: State, sk: bytes, dh_pk_r: X448PublicKey):
  assert(isinstance(state, State))
  assert(isinstance(sk, bytes))
  assert(isinstance(dh_pk_r, X448PublicKey))

  state.dh_pair = gen_dh_keys()
  state.dh_pk_r = dh_pk_r

  state.rk = sk
  state.ck_s = None
  state.ck_r = None

  state.delayed_send_ratchet = True

  state.send_msg_no = 0
  state.recv_msg_no = 0
  state.prev_chain_len = 0

  state.skipped_mks = OrderedDict()
  state.skipped_lifetimes = []

# Sets initial sender state (header encryption variant)
def init_sender_he(state: State, sk: bytes, dh_pk_r: X448PublicKey,
    hk_s: bytes, next_hk_r: bytes):
  assert(isinstance(state, State))
  assert(isinstance(sk, bytes))
  assert(isinstance(dh_pk_r, X448PublicKey))
  assert(isinstance(hk_s, bytes))
  assert(isinstance(next_hk_r, bytes))

  state.dh_pair = gen_dh_keys()
  state.dh_pk_r = dh_pk_r

  state.rk = sk
  state.ck_s = None
  state.ck_r = None

  state.hk_s = hk_s
  state.hk_r = None
  state.next_hk_s = None
  state.next_hk_r = next_hk_r

  state.delayed_send_ratchet = True

  state.send_msg_no = 0
  state.recv_msg_no = 0
  state.prev_chain_len = 0

  state.skipped_mks = OrderedDict()
  state.skipped_lifetimes = []

# Sets initial receiver state (header encryption variant)
def init_receiver(state: State, sk: bytes, dh_pair: X448PrivateKey):
  assert(isinstance(state, State))
  assert(isinstance(sk, bytes))
  assert(isinstance(dh_pair, X448PrivateKey))

  state.dh_pair = dh_pair
  state.dh_pk_r = None

  state.rk = sk
  state.ck_s = None
  state.ck_r = None

  state.delayed_send_ratchet = False

  state.send_msg_no = 0
  state.recv_msg_no = 0
  state.prev_chain_len = 0

  state.skipped_mks = OrderedDict()
  state.skipped_lifetimes = []

# Sets initial receiver state (header encryption variant)
def init_receiver_he(state: State, sk: bytes, dh_pair: X448PrivateKey, 
    next_hk_s: bytes, next_hk_r: bytes):
  assert(isinstance(state, State))
  assert(isinstance(sk, bytes))
  assert(isinstance(dh_pair, X448PrivateKey))
  assert(isinstance(next_hk_s, bytes))
  assert(isinstance(next_hk_r, bytes))

  state.dh_pair = dh_pair
  state.dh_pk_r = None

  state.rk = sk
  state.ck_s = None
  state.ck_r = None

  state.hk_s = None
  state.hk_r = None
  state.next_hk_s = next_hk_s
  state.next_hk_r = next_hk_r

  state.delayed_send_ratchet = False

  state.send_msg_no = 0
  state.recv_msg_no = 0
  state.prev_chain_len = 0

  state.skipped_mks = OrderedDict()
  state.skipped_lifetimes = []

# Returns encrypted message
def ratchet_encrypt(state: State, pt: str, associated_data: bytes):
  assert(isinstance(state, State))
  assert(isinstance(pt, str))
  assert(isinstance(associated_data, bytes))

  if state.delayed_send_ratchet:
    state.rk, state.ck_s, state.next_hk_s = ratchet_root(
      get_dh_out(state.dh_pair, state.dh_pk_r), state.rk)
    state.delayed_send_ratchet = False

  old_ck = state.ck_s
  old_msg_no = state.send_msg_no

  state.ck_s, mk = ratchet_chain(state.ck_s)
  header = Header(state.dh_pair.public_key(), 
    state.prev_chain_len, state.send_msg_no)
  state.send_msg_no += 1

  ct, ret = encrypt_gcm(mk, pt.encode("utf-8"), associated_data + bytes(header))
  if ret != CRYPTO_RET.SUCCESS: # restore state on fail
    state.ck_r = old_ck
    state.send_msg_no = old_msg_no
    return None
  
  return Message(header, ct)

# Returns encrypted header and ciphertext for encrypted message
def ratchet_encrypt_he(state: State, pt: str, associated_data: bytes):
  assert(isinstance(state, State))
  assert(isinstance(pt, str))
  assert(isinstance(associated_data, bytes))

  if state.delayed_send_ratchet:
    state.rk, state.ck_s, state.next_hk_s = ratchet_root(
      get_dh_out(state.dh_pair, state.dh_pk_r), state.rk)
    state.delayed_send_ratchet = False

  old_ck = state.ck_s
  old_msg_no = state.send_msg_no

  state.ck_s, mk = ratchet_chain(state.ck_s)
  header = Header(state.dh_pair.public_key(), 
    state.prev_chain_len, state.send_msg_no)
  hdr_ct, ret = encrypt_gcm(state.hk_s, bytes(header), b"")

  if ret != CRYPTO_RET.SUCCESS: # restore state on fail
    state.ck_r = old_ck 
    state.send_msg_no = old_msg_no
    return None

  state.send_msg_no += 1

  ct, ret = encrypt_gcm(mk, pt.encode("utf-8"), associated_data + hdr_ct)
  if ret != CRYPTO_RET.SUCCESS: # restore state on fail
    state.ck_r = old_ck
    state.send_msg_no = old_msg_no
    return None
  
  return MessageHE(hdr_ct, ct)

# Returns plaintext message from encrypted message
def ratchet_decrypt(state: State, msg: Message, associated_data: bytes):
  assert(isinstance(state, State))
  assert(isinstance(msg, Message))
  assert(isinstance(associated_data, bytes))

  pt = try_skipped_mks(state, msg.header, msg.ct, associated_data)
  if pt != None:
    update_event_counter(state) # successful decrypt event
    delete_old_skipped_mks(state)
    return pt
  
  old_state = copy(state)

  if not pks_equal(msg.header.dh_pk, state.dh_pk_r): 
    try:
      skip_over_mks(state, msg.header.prev_chain_len, 
        state.dh_pk_r) # save mks from old recv chain
    except:
      restore_old_state(state, old_state)
      return None
    
    dh_ratchet(state, msg.header.dh_pk)

  try:
    skip_over_mks(state, msg.header.msg_no,
      state.dh_pk_r) # save mks on new sending chain
  except:
    restore_old_state(state, old_state)
    return None

  state.ck_r, mk = ratchet_chain(state.ck_r)
  state.recv_msg_no += 1

  pt_bytes, ret = decrypt_gcm(mk, msg.ct, associated_data + bytes(msg.header))
  if ret != CRYPTO_RET.SUCCESS:
    restore_old_state(state, old_state)
    return None

  update_event_counter(state) # successful decrypt event
  delete_old_skipped_mks(state)
  
  return pt_bytes.decode("utf-8")

# Returns plaintext message from encrypted header and ciphertext 
def ratchet_decrypt_he(state: State, msg: MessageHE, associated_data: bytes):
  assert(isinstance(state, State))
  assert(isinstance(msg, MessageHE))
  assert(isinstance(associated_data, bytes))

  pt = try_skipped_mks_he(state, msg.hdr_ct, msg.ct, associated_data)
  if pt != None:
    update_event_counter(state) # successful decrypt event
    delete_old_skipped_mks(state)
    return pt

  old_state = copy(state)

  try:
    header, should_dh_ratchet = decrypt_header(state, msg.hdr_ct)
  except:
    restore_old_state(state, old_state)
    return None

  if should_dh_ratchet:
    try:
      skip_over_mks(state, header.prev_chain_len,
        state.hk_r) # save mks from old recv chain
      dh_ratchet_he(state, header.dh_pk)
    except:
      restore_old_state(state, old_state)
      return None

  try:
    skip_over_mks(state, header.msg_no,
      state.hk_r) # save mks on new sending chain
  except:
    restore_old_state(state, old_state)
    return None
  
  state.ck_r, mk = ratchet_chain(state.ck_r)
  state.recv_msg_no += 1

  pt_bytes, ret = decrypt_gcm(mk, msg.ct, associated_data + msg.hdr_ct)
  if ret != CRYPTO_RET.SUCCESS:
    restore_old_state(state, old_state)
    return None

  update_event_counter(state) # successful decrypt event
  delete_old_skipped_mks(state)
  
  return pt_bytes.decode("utf-8")

# Returns plain text if the message corresponds to a skipped message key,
# deleting the key from the saved key map
def try_skipped_mks(state: State, header: Header, ct: bytes, 
    associated_data: bytes):
  assert(isinstance(state, State))
  assert(isinstance(header, Header))
  assert(isinstance(ct, bytes))
  assert(isinstance(associated_data, bytes))
  
  hdr_pk_bytes = dh_pk_bytes(header.dh_pk)

  if (hdr_pk_bytes, header.msg_no) in state.skipped_mks:
    mk = state.skipped_mks[(hdr_pk_bytes, header.msg_no)]
    del state.skipped_mks[(hdr_pk_bytes, header.msg_no)]

    pt_bytes, ret = decrypt_gcm(
      mk, ct, associated_data + bytes(header))
    if ret == CRYPTO_RET.SUCCESS:
      return pt_bytes.decode("utf-8")

  return None

# Returns plain text if the message corresponds to a skipped message key,
# deleting the key from the saved key map (header encryption variant)
def try_skipped_mks_he(state: State, hdr_ct: bytes, ct: bytes, 
    associated_data: bytes):
  assert(isinstance(state, State))
  assert(isinstance(hdr_ct, bytes))
  assert(isinstance(ct, bytes))
  assert(isinstance(associated_data, bytes))

  i = 0
  for ((hk_r, msg_no), mk) in state.skipped_mks.items():
    hdr_pt_bytes, ret = decrypt_gcm(hk_r, hdr_ct, b"")
    header = header_from_bytes(hdr_pt_bytes)
    
    if ret == CRYPTO_RET.SUCCESS and header.msg_no == msg_no:
      del state.skipped_mks[(hk_r, msg_no)]
      state.skipped_lifetimes.pop(i)

      pt_bytes, ret = decrypt_gcm(
        mk, ct, associated_data + hdr_ct)
      if ret == CRYPTO_RET.SUCCESS:
        return pt_bytes.decode("utf-8")
      else:
        break
    
    i += 1

  return None

# Returns header and whether ratchet is needed. Tries current and next 
# header receiving keys when decrypting
# Raises exception on error
def decrypt_header(state: State, hdr_ct):
  assert(isinstance(state, State))
  assert(isinstance(hdr_ct, bytes))

  if state.hk_r != None: # may not have ratcheted yet
    hdr_pt_bytes, ret = decrypt_gcm(state.hk_r, hdr_ct, b"")
    if ret == CRYPTO_RET.SUCCESS:
      return header_from_bytes(hdr_pt_bytes), False

  hdr_pt_bytes, ret = decrypt_gcm(state.next_hk_r, hdr_ct, b"")  
  if ret == CRYPTO_RET.SUCCESS:
    return header_from_bytes(hdr_pt_bytes), True

  raise Exception("Error: invalid header ciphertext.")

# If new ratchet key received then store skipped message keys 
# from receiving chain and ratchet receiving chain (header 
# encryption variant)
# Raises exception on error
def skip_over_mks(state: State, end_msg_no: int, map_key: bytes):
  assert(isinstance(state, State))
  assert(isinstance(end_msg_no, int))

  if state.recv_msg_no + MAX_SKIP < end_msg_no:
    raise Exception("Error: end message number out of range.")
  elif state.ck_r != None and state.hk_r != None:
    while state.recv_msg_no < end_msg_no:
      state.ck_r, mk = ratchet_chain(state.ck_r)

      if len(state.skipped_mks) == MAX_SKIP: # delete oldest key to make space
        del state.skipped_mks[next(iter(state.skipped_mks))]
        state.skipped_lifetimes.pop()

      state.skipped_mks[(map_key, state.recv_msg_no)] = mk

      if len(state.skipped_lifetimes) == 0:
        state.skipped_lifetimes.append(DELETE_MIN_EVENTS)
      else:
        # FIXME: something wrong here
        state.skipped_lifetimes.append(
          max(DELETE_MIN_EVENTS - state.skipped_lifetimes[0], 1)
        )
      state.recv_msg_no += 1

# Performs DH-ratchet step, updating the root chain twice and
# so resetting sending/receiving chains
def dh_ratchet(state: State, dh_pk_r: X448PublicKey):
  assert(isinstance(state, State))
  assert(isinstance(dh_pk_r, X448PublicKey))

  if state.delayed_send_ratchet: 
    state.rk, state.ck_s, _ = ratchet_root(
      get_dh_out(state.dh_pair, state.dh_pk_r), state.rk)

  state.dh_pk_r = dh_pk_r
  state.rk, state.ck_r, _ = ratchet_root(
    get_dh_out(state.dh_pair, state.dh_pk_r), state.rk)
  state.dh_pair = gen_dh_keys()
  state.delayed_send_ratchet = True
  state.prev_chain_len = state.send_msg_no
  state.send_msg_no = 0
  state.recv_msg_no = 0

# Performs DH-ratchet step, updating the root chain twice and
# so resetting sending/receiving chains (header encryption variant)
def dh_ratchet_he(state: State, dh_pk_r: X448PublicKey):
  assert(isinstance(state, State))
  assert(isinstance(dh_pk_r, X448PublicKey))

  if state.delayed_send_ratchet: 
    state.rk, state.ck_s, state.next_hk_s = ratchet_root(
      get_dh_out(state.dh_pair, state.dh_pk_r), state.rk)

  state.dh_pk_r = dh_pk_r
  state.hk_s = state.next_hk_s
  state.hk_r = state.next_hk_r
  state.rk, state.ck_r, state.next_hk_r = ratchet_root(
    get_dh_out(state.dh_pair, state.dh_pk_r), state.rk)
  state.dh_pair = gen_dh_keys()
  state.delayed_send_ratchet = True
  state.prev_chain_len = state.send_msg_no
  state.send_msg_no = 0
  state.recv_msg_no = 0

# Update oldest skipped mk lifetime.
def update_event_counter(state: State):
  assert(isinstance(state, State))

  if len(state.skipped_lifetimes) > 0:
    state.skipped_lifetimes[0] -= 1

# Deletes oldest skipped mk after it has been in storage for
# DELETE_EVENT_NUM decrypt events. Ensures mks aren't stored indefinitely.
def delete_old_skipped_mks(state: State):
  assert(isinstance(state, State))

  if len(state.skipped_lifetimes) > 0 and state.skipped_lifetimes[0] == 0:
    del state.skipped_mks[next(iter(state.skipped_mks))]
    state.skipped_lifetimes.pop()
