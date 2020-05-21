from __future__ import absolute_import

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from ..interfaces.kdfchain import KDFChainIface, SymmetricChainIface
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
    mk = hmac(self._ck, b"mk_ratchet", SHA256, default_backend())
    self._ck = hmac(self._ck, b"ck_ratchet", SHA256, default_backend())
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
  def msg_no(self):
    return self._msg_no

  @msg_no.setter
  def msg_no(self, val):
    self._msg_no = val


class RootChain(KDFChainIface):
  KEY_LEN = 32

  def __init__(self, ck = None, outputs = 2):
    if ck:
      if not isinstance(ck, bytes):
        raise TypeError("ck must be of type: bytes")
      if not len(ck) == RootChain.KEY_LEN:
        raise ValueError("ck must be 32 bytes")
      self._ck = ck
    else:
      self._ck = None

    if not isinstance(outputs, int):
      raise TypeError("outputs must be of type: int")
    if outputs < 0:
      raise ValueError("outputs must be positive")
    self._outputs = outputs

  def ratchet(self):
    hkdf_out = hkdf(
      self._ck, 
      RootChain.KEY_LEN * (self._outputs + 1),
      b"rk_ratchet", 
      SHA256, 
      default_backend()
    )

    self._rk = hkdf_out[:RootChain.KEY_LEN]

    keys = []
    for i in range(1, self._outputs):
      keys.append(hkdf_out[i * RootChain.KEY_LEN:(i + 1) * RootChain.KEY_LEN])

    return keys

  def serialize(self):
    return {
      "ck" : self._ck,
      "outputs" : self._outputs
    }

  @classmethod
  def deserialize(cls, serialized_chain):
    return cls(serialized_chain["ck"], serialized_chain["outputs"])
