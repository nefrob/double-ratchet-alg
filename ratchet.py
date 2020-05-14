'''
Resilience: The output keys appear random to an adversary without
knowledge of the KDF keys. This is true even if the adversary can 
control the KDF inputs.
"PRF"

Forward security: Output keys from the past appear random to 
an adversary who learns the KDF key at some point in time.

Break-in recovery: Future output keys appear random to an 
adversary who learns the KDF key at some point in time, 
provided that future inputs have added sufficient entropy.

The Double Ratchet algorithm is used by two parties to exchange
sencrypted messages based on a shared secret key. Typically the
parties will use some key agreement protocol (such as X3DH [1])
to agree on the shared secret key. Following this, the parties 
will use the Double Ratchet to send and receive encrypted messages.

Initial root key from shared secret (X3DH probably)

Ref: https://signal.org/docs/specifications/doubleratchet/
'''

import utils
import crypto_utils

# Max number of message keys that can be skipped in a single chain
MAX_SKIP = 50


'''
TODO:
'''
def init_sender(state, sk, peer_pk, ck_r = None):
  state.dh_pair = crypto_utils.gen_dh_keys()
  state.peer_pk = peer_pk
  state.rk, state.ck_s = crypto_utils.ratchet_root(crypto_utils.get_dh_out(state.dh_pair, peer_pk), sk)
  state.ck_r = ck_r
  state.send_msg_no = 0
  state.recv_msg_no = 0
  state.prev_chain_len = 0
  state.skipped_mks = {}


'''
TODO:
'''
def init_receiver(state, sk, dh_pair, ck_s = None):
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
TODO:
'''
def encrypt_msg(state, pt, associated_data):
  state.ck_s, mk = crypto_utils.ratchet_chain(state.ck_s)
  header = utils.build_header(state.dh_pair, 
    state.prev_chain_len, state.send_msg_no)
  state.send_msg_no += 1

  return header, crypto_utils.encrypt(mk, pt, 
    utils.encode_header(associated_data, header))


'''
This function then stores any skipped message keys from the current receiving
 chain, performs a symmetric-key ratchet step to derive the relevant message 
 key and next chain key, and decrypts the message.



TODO: If an exception is raised (e.g. message authentication failure) then the message
 is discarded and changes to the state object are discarded. Otherwise, the
  decrypted plaintext is accepted and changes to the state object are stored:
'''
def decrypt_msg(state, header, ct, associated_data):
  pt = try_skipped_mks(state, header, ct, associated_data)
  if pt != None:
    return pt
  
  if header.peer_pk != state.peer_pk: # save mks on old recv chain
    skip_over_mks(state, header.prev_chain_len) # FIXME: check for too many missed msgs err
    dh_ratchet(state, header)
  
  skip_over_mks(state, header.msg_no) # save mks on new sending chain
  state.ck_r, mk = crypto_utils.ratchet_chain(state.ck_r)
  state.send_msg_no += 1
  return crypto_utils.decrypt(
    mk, ct, utils.encode_header(associated_data, header)
  )


'''
Returns plain text if the message corresponds to a skipped message key,
deleting the key from the saved key map.
'''
def try_skipped_mks(state, header, ct, associated_data):
  if (header.pk, header.msg_no) in state.skipped_mks:
    mk = state.skipped_mks[(header.pk, header.msg_no)]
    del state.skipped_mks[(header.pk, header.msg_no)]
    return crypto_utils.decrypt(mk, ct, utils.encode_header(associated_data, header))
  else:
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
      state.skipped_mks[(state.peer_pk, state.recv_msg_no)] = mk
      state.recv_msg_no += 1


'''
TODO:

dh ratchet root and send/recv for new chains
'''
def dh_ratchet(state, header):
  state.peer_pk = header.peer_pk
  state.rk, state.ck_r = crypto_utils.ratchet_root(
    crypto_utils.get_dh_out(state.dh_pair, state.peer_pk), state.rk
  )
  state.dh_pair = crypto_utils.gen_dh_keys()
  state.rk, state.ck_s = crypto_utils.ratchet_root(
    crypto_utils.get_dh_out(state.dh_pair, state.peer_pk), state.rk
  )
  state.prev_chain_len = state.send_msg_no
  state.send_msg_no = 0
  state.recv_msg_no = 0
