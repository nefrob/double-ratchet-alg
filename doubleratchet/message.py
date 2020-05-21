from __future__ import absolute_import

from .crypto.dhkey import DHPublicKey


class Header:
  """TODO:"""

  INT_ENCODE_BYTES = 4 # number of int bytes use when encoding a header

  def __init__(self, dh_pk, prev_chain_len, msg_no):
    # TODO: check for errors?

    self._dh_pk = dh_pk
    self._prev_chain_len = prev_chain_len
    self._msg_no = msg_no

  def __bytes__(self):
    header_bytes = self._dh_pk.pk_bytes()
    header_bytes += self._prev_chain_len.to_bytes(
      Header.INT_ENCODE_BYTES, 
      byteorder='little'
    )
    header_bytes += self._msg_no.to_bytes(
      Header.INT_ENCODE_BYTES, 
      byteorder='little'
    )

    return header_bytes

  @classmethod
  def from_bytes(cls, header_bytes):
    if header_bytes == None or \
      len(header_bytes) != DHPublicKey.KEY_LEN + 2 * Header.INT_ENCODE_BYTES:
      raise ValueError("Inva")

    dh_pk = DHPublicKey.from_bytes(header_bytes[:DHPublicKey.KEY_LEN])
    prev_chain_len = int.from_bytes(
      header_bytes[DHPublicKey.KEY_LEN:-Header.INT_ENCODE_BYTES], 
      byteorder='little'
    )
    msg_no = int.from_bytes(
      header_bytes[-Header.INT_ENCODE_BYTES:], 
      byteorder='little'
    )
    
    return cls(dh_pk, prev_chain_len, msg_no)

  # TODO: getters/setters?

  @property
  def dh_pk(self):
    return self._dh_pk

  @property
  def prev_chain_len(self):
    return self._prev_chain_len

  @property
  def msg_no(self):
    return self._msg_no


# Ratchet message to transmit
class Message:
  def __init__(self, header, ct):
    self._header = header
    self._ct = ct

  @property
  def header(self):
    return self._header

  @property
  def ct(self):
    return self._ct


# Ratchet message using header encryption
class MessageHE:
  def __init__(self, header_ct, ct):
    self._header_ct = header_ct
    self._ct = ct

  @property
  def header_ct(self):
    return self._header_ct

  @property
  def ct(self):
    return self._ct
    