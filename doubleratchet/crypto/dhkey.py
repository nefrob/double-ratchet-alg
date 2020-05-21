from __future__ import absolute_import
from secrets import token_bytes

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

from ..interfaces.dhkey import DHKeyPairIface, DHPublicKeyIface


class DHKeyPair(DHKeyPairIface):
  def __init__(self, dh_pair = None):
    if dh_pair:
      if not isinstance(dh_pair, X448PrivateKey):
        raise TypeError("dh_pair must be of type: X448PrivateKey")
      self._private_key = dh_pair
    else:
      self._private_key = X448PrivateKey.generate()
    self._public_key = self._private_key.public_key()

  @classmethod
  def generate_dh(cls):
    return cls(X448PrivateKey.generate())

  @staticmethod
  def dh_out(priv_a, pub_b):
    if not isinstance(priv_a, X448PrivateKey):
      raise TypeError("priv_a must be of type: X448PrivateKey")
    if not isinstance(pub_b, X448PublicKey):
      raise TypeError("pub_b must be of type: X448PublicKey")
  
    return priv_a.exchange(pub_b)

  def serialize(self):
    return {
      "private_key" : self._sk_bytes().hex(),
      "public_key" : pk_bytes(self._public_key).hex()
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


class DHPublicKey(DHPublicKeyIface):
  KEY_LEN = 56

  def __init__(self, public_key):
    if not isinstance(public_key, X448PublicKey):
      raise TypeError("public_key must be of type: X448PublicKey")
    self._public_key = public_key

  def pk_bytes(self):
    return pk_bytes(self._public_key)

  @classmethod
  def from_bytes(cls, pk_bytes):
    return cls(X448PublicKey.from_public_bytes(pk_bytes))

  @property
  def public_key(self):
    return self._public_key

  def serialize(self):
    return {
      "public_key": pk_bytes(self._public_key).hex()
    }
  
  @classmethod
  def deserialize(cls, serialized_pk):
    public_key = X448PublicKey.from_public_bytes(
      bytes.fromhex(serialized_pk["public_key"])
    )
    return cls(public_key)


# TODO:
def pk_bytes(pk):
  return pk.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
  )
