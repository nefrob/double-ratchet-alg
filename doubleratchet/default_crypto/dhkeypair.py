from __future__ import absolute_import
from secrets import token_bytes

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

from ..interfaces.dhkeypair import DHKeyPairIface


class DHKeyPair(DHKeyPairIface):
  def __init__(self, dh_pair: X448PrivateKey = None):
    if dh_pair:
      self._private_key = dh_pair
    else:
      self._private_key = X448PrivateKey.generate()
    self._public_key = self._private_key.public_key()

  @classmethod
  def generate_dh(cls):
    return cls(X448PrivateKey.generate())

  @staticmethod
  def dh_out(priv_a: X448PrivateKey, pub_b: X448PublicKey):
    return priv_a.exchange(pub_b)

  def serialize(self):
    return {
      "private_key" : self._sk_bytes().hex(),
      "public_key" : self._pk_bytes().hex()
    }

  @classmethod
  def deserialize(cls, serialized_dh):
    private_key = X448PrivateKey.from_private_bytes(
      bytes.fromhex(serialized_dh["private_key"])
    )
    return cls(private_key)

  @property
  def private_key(self):
    self._private_key

  @property
  def public_key(self):
    return self._public_key

  def _sk_bytes(self):
    return self._private_key.private_bytes(
      encoding=serialization.Encoding.Raw,
      format=serialization.PrivateFormat.Raw,
      encryption_algorithm=serialization.NoEncryption()
    )

  def _pk_bytes(self):
    return self._public_key.public_bytes(
      encoding=serialization.Encoding.Raw,
      format=serialization.PublicFormat.Raw
    )