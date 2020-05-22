from __future__ import absolute_import

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from ..interfaces.kdfchain import RootChainIface, SymmetricChainIface
from .utils import hkdf, hmac


class SymmetricChain(SymmetricChainIface):
  def __init__(self, ck = None, msg_no = None):
    if ck:
      if not isinstance(ck, bytes):
        raise TypeError("ck must be of type: bytes")
      self._ck = ck
    else:
      self._ck = None

    if msg_no:
      if not isinstance(msg_no, int):
        raise TypeError("msg_no must be of type: int")
      if msg_no < 0:
        raise ValueError("msg_no  must be positive")
      self._msg_no = msg_no
    else:
      self._msg_no = 0

  def ratchet(self):
    if self._ck == None:
      raise ValueError("ck is not initialized")

    self._msg_no += 1

    mk = hmac(self._ck, b"mk_ratchet", SHA256(), default_backend())
    self._ck = hmac(self._ck, b"ck_ratchet", SHA256(), default_backend())
    
    return mk

  def serialize(self):
    return {
      "ck" : self._ck,
      "msg_no" : self._msg_no
    }

  @classmethod
  def deserialize(cls, serialized_chain):
    return cls(serialized_chain["ck"], serialized_chain["msg_no"])
  
  @property
  def ck(self):
    return self._ck

  @ck.setter
  def ck(self, val):
    self._ck = val

  @property
  def msg_no(self):
    return self._msg_no

  @msg_no.setter
  def msg_no(self, val):
    self._msg_no = val


class RootChain(RootChainIface):
  KEY_LEN = 32
  DEFAULT_OUTPUTS = 1

  def __init__(self, ck = None):
    if ck:
      if not isinstance(ck, bytes):
        raise TypeError("ck must be of type: bytes")
      if not len(ck) == RootChain.KEY_LEN:
        raise ValueError("ck must be 32 bytes")
      self._ck = ck
    else:
      self._ck = None

  def ratchet(self, dh_out, outputs = DEFAULT_OUTPUTS):
    if not isinstance(dh_out, bytes):
      raise TypeError("dh_out must be of type: bytes")
    if not isinstance(outputs, int):
      raise TypeError("outputs must be of type: int")
    if outputs < 0:
      raise ValueError("outputs must be positive")
    if self._ck == None:
      raise ValueError("ck is not initialized")

    hkdf_out = hkdf(
      dh_out, 
      RootChain.KEY_LEN * (outputs + 1),
      self._ck,
      b"rk_ratchet", 
      SHA256(), 
      default_backend()
    )

    self._rk = hkdf_out[-RootChain.KEY_LEN:]

    keys = []
    for i in range(0, outputs):
      keys.append(hkdf_out[i * RootChain.KEY_LEN:(i + 1) * RootChain.KEY_LEN])

    return keys

  def serialize(self):
    return {
      "ck" : self._ck
    }

  @classmethod
  def deserialize(cls, serialized_chain):
    return cls(serialized_chain["ck"])

  @property
  def ck(self):
    return self._ck

  @ck.setter
  def ck(self, val):
    self._ck=  val
