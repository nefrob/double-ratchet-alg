from __future__ import absolute_import

from .interfaces.aead import AEADIFace
from .interfaces.dhkey import DHKeyPairIface
from .interfaces.ratchet import RatchetIface
from .message import Header, Message
from .state import State


class Ratchet(RatchetIface):
  MAX_SKIP = 1000

  @staticmethod
  def encrypt_message(state, pt, associated_data, aead):
    if not isinstance(state, State):
      raise TypeError("state must be of type: state")
    if not isinstance(pt, str):
      raise TypeError("pt must be of type: string")
    if not isinstance(associated_data, bytes):
      raise TypeError("associated_data must be of type: bytes")
    if not issubclass(aead, AEADIFace):
      raise TypeError("aead must implement AEADIface")

    if state._delayed_send_ratchet:
      state.send.ck = state.root.ratchet(state.dh_pair.dh_out(state.dh_pk_r))[0]
      state.delayed_send_ratchet = False

    mk = state.send.ratchet()
    header = Header(state.dh_pair.public_key, 
      state.prev_send_len, state.send.msg_no)

    ct = aead.encrypt(mk, pt.encode("utf-8"), associated_data + bytes(header))

    return Message(header, ct)

  @staticmethod
  def decrypt_message(state, msg, associated_data, aead, keypair):
    if not isinstance(state, State):
      raise TypeError("state must be of type: state")
    if not isinstance(msg, Message):
      raise TypeError("msg must be of type: Message")
    if not isinstance(associated_data, bytes):
      raise TypeError("associated_data must be of type: bytes")
    if not issubclass(aead, AEADIFace):
      raise TypeError("aead must implement AEADIface")
    if not issubclass(keypair, DHKeyPairIface):
      raise TypeError("keypair must implement DHKeyPairIface")

    pt = try_skipped_mks(state, msg.header, msg.ct, associated_data, aead)
    if pt != None:
      state.skipped_mks.notify_event() # successful decrypt event
      return pt

    if not state.dh_pk_r:
      dh_ratchet(state, msg.header.dh_pk, keypair)
    elif not state.dh_pk_r.is_equal_to(msg.header.dh_pk): 
      skip_over_mks(state, msg.header.prev_chain_len, 
        state.dh_pk_r.pk_bytes()) # save mks from old recv chain
      dh_ratchet(state, msg.header.dh_pk, keypair)

    skip_over_mks(state, msg.header.prev_chain_len, 
      state.dh_pk_r.pk_bytes())  # save mks on new sending chain

    mk = state.receive.ratchet()

    pt_bytes = aead.decrypt(mk, msg.ct, associated_data + bytes(msg.header))
    state.skipped_mks.notify_event() # successful decrypt event
    
    return pt_bytes.decode("utf-8")


# TODO:
def try_skipped_mks(state, header, ct, associated_data, aead):
  hdr_pk_bytes = header.dh_pk.pk_bytes()
  mk = state.skipped_mks.lookup((hdr_pk_bytes, header.msg_no))
  if mk:
    state.skipped_mks.delete((hdr_pk_bytes, header.msg_no))

    pt_bytes = aead.decrypt(mk, ct, associated_data + bytes(header))
    return pt_bytes.decode("utf-8")

  return None

# TODO:
def skip_over_mks(state, end_msg_no, map_key):
  if state.receive.msg_no + Ratchet.MAX_SKIP < end_msg_no:
    raise ValueError("Received message number too large," 
      "cannot store all skipped mks.")
  elif state.receive.ck != None:
    while state.receive.msg_no < end_msg_no:
      mk = state.receive.ratchet()

      if state.skipped_mks.count() == Ratchet.MAX_SKIP: # del keys FIFO
        state.skipped_mks.delete(state.skipped_mks.front())

      state.skipped_mks.put((map_key, state.recv_msg_no), mk)

# TODO:
def dh_ratchet(state, dh_pk_r, keypair):
  if state.delayed_send_ratchet: 
    state.send.ck = state.root.ratchet(state.dh_pair.dh_out(state.dh_pk_r))[0]

  state.dh_pk_r = dh_pk_r
  state.receive.ck = state.root.ratchet(state.dh_pair.dh_out(state.dh_pk_r))[0]

  state.dh_pair = keypair.generate_dh()
  state.delayed_send_ratchet = True
  state.prev_send_len = state.send.msg_no
  state.send.msg_no = 0
  state.receive.msg_no = 0
