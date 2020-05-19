from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey

from .crypto_utils import dh_pk_bytes # for header encoding
from .crypto import X448_KEY_BYTES

INT_ENCODE_BYTES = 4 # number of int bytes use when encoding a header


# Message header
class Header:
  def __init__(self, dh_pk: X448PublicKey, prev_chain_len: int, msg_no: int):
    assert(isinstance(dh_pk, X448PublicKey))
    assert(isinstance(prev_chain_len, int))
    assert(isinstance(msg_no, int))

    self.dh_pk = dh_pk
    self.prev_chain_len = prev_chain_len
    self.msg_no = msg_no

  def __bytes__(self):
    header_bytes = dh_pk_bytes(self.dh_pk)
    header_bytes += self.prev_chain_len.to_bytes(INT_ENCODE_BYTES, byteorder='little')
    header_bytes += self.msg_no.to_bytes(INT_ENCODE_BYTES, byteorder='little')

    return header_bytes


# Ratchet message to transmit
class Message:
  def __init__(self, header: Header, ct: bytes):
    assert(isinstance(header, Header))
    assert(isinstance(ct, bytes))

    self.header = header
    self.ct = ct


# Ratchet message using header encryption
class MessageHE:
  def __init__(self, hdr_ct: bytes, ct: bytes):
    assert(isinstance(hdr_ct, bytes))
    assert(isinstance(ct, bytes))

    self.hdr_ct = hdr_ct
    self.ct = ct


# Return header from bytes array
def header_from_bytes(header_bytes: bytes):
  if header_bytes == None or \
      len(header_bytes) != X448_KEY_BYTES + 2 * INT_ENCODE_BYTES:
    return None

  dh_pk = X448PublicKey.from_public_bytes(header_bytes[:X448_KEY_BYTES])
  prev_chain_len = int.from_bytes(
    header_bytes[X448_KEY_BYTES:-INT_ENCODE_BYTES], byteorder='little')
  msg_no = int.from_bytes(header_bytes[-INT_ENCODE_BYTES:], byteorder='little')
  
  return Header(dh_pk, prev_chain_len, msg_no)
