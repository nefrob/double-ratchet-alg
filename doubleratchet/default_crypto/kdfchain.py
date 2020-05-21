from __future__ import absolute_import

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..interfaces.kdfchain import KDFChainIface


class SymmetricChain(KDFChainIface):

  HASH_FUNCTIONS = {
    "sha256": hashes.SHA256,
    "sha512": hashes.SHA512
  }

  def __init__(self, ck = None):
    if ck:
      self._ck = ck
    else:
      self._ck = None

  def ratchet(self):
    pass

  def serialize(self):
    pass

  @classmethod
  def deserialize(cls):
    pass

  @staticmethod
  def _hmac(ck):
    pass

class RootChain(KDFChainIface):

  HASH_FUNCTIONS = {
    "sha256": hashes.SHA256,
    "sha512": hashes.SHA512
  }

  def __init__(self, ck = None, hash_alg = hashes.SHA256):
    if ck:
      self._ck = ck
    else:
      self._ck = None

    if hash_alg not in RootChain.HASH_FUNCTIONS:
      raise ValueError("Invalid hash algorithm provided.")
    else:
      self.hash_alg = hash_alg

  def ratchet(self):
    return 

  def serialize(self):
    pass

  @classmethod
  def deserialize(cls):
    pass
