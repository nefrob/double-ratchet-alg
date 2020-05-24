from __future__ import absolute_import

from .crypto.dhkey import DHPublicKey


# Double Ratchet message header
class Header:
  INT_ENCODE_BYTES = 4 # number of int bytes use when encoding a header

  def __init__(self, dh_pk, prev_chain_len, msg_no):
    if not isinstance(dh_pk, DHPublicKey):
      raise TypeError("dh_pk must be of type: DHPublicKey")
    if not isinstance(prev_chain_len, int):
      raise TypeError("prev_chain_len must be of type: int")
    if  prev_chain_len < 0:
      raise ValueError("prev_chain_len must be positive")
    if not isinstance(msg_no, int):
      raise TypeError("msg_no must be of type: int")
    if msg_no < 0:
      raise ValueError("msg_no must be positive")

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
    if not isinstance(header_bytes, bytes):
      raise TypeError("header_bytes must be of type: bytes")

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

  # Getters/setters

  @property
  def dh_pk(self):
    return self._dh_pk

  @property
  def prev_chain_len(self):
    return self._prev_chain_len

  @property
  def msg_no(self):
    return self._msg_no


# Ratchet message
class Message:
  def __init__(self, header, ct):
    if not isinstance(header, Header):
      raise TypeError("header must be of type: Header")
    if not isinstance(ct, bytes):
      raise TypeError("ct must be of type: bytes")

    self._header = header
    self._ct = ct

  # Getters/setters

  @property
  def header(self):
    return self._header

  @property
  def ct(self):
    return self._ct

# Ratchet message (header encryption variant)
class MessageHE:
  def __init__(self, header_ct, ct):
    if not isinstance(header_ct, bytes):
      raise TypeError("header_ct must be of type: bytes")
    if not isinstance(ct, bytes):
      raise TypeError("ct must be of type: bytes")

    self._header_ct = header_ct
    self._ct = ct

  # Getters/setters

  @property
  def header_ct(self):
    return self._header_ct

  @property
  def ct(self):
    return self._ct
    