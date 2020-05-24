from __future__ import absolute_import

from cryptography.hazmat.primitives import serialization

# DH using Curve448
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

from ..interfaces.dhkey import DHKeyPairIface, DHPublicKeyIface


class DHKeyPair(DHKeyPairIface):
  """An implementation of the DHKeyPair Interface."""
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

  def dh_out(self, dh_pk):
    if not isinstance(dh_pk, DHPublicKey):
      raise TypeError("dh_pk must be of type: DHPublicKey")
  
    return self._private_key.exchange(dh_pk.public_key)

  def serialize(self):
    return {
      "private_key" : self._sk_bytes().hex(),
      "public_key" : pk_bytes(self._public_key).hex()
    }

  @classmethod
  def deserialize(cls, serialized_dh):
    if not isinstance(serialized_dh, dict):
      raise TypeError("serialized_dh must be of type: dict")

    private_key = X448PrivateKey.from_private_bytes(
      bytes.fromhex(serialized_dh["private_key"])
    )
    return cls(private_key)

  @property
  def private_key(self):
    self._private_key

  @property
  def public_key(self):
    return DHPublicKey(self._public_key)

  # Returns private key in bytes form
  def _sk_bytes(self):
    return self._private_key.private_bytes(
      encoding=serialization.Encoding.Raw,
      format=serialization.PrivateFormat.Raw,
      encryption_algorithm=serialization.NoEncryption()
    )


class DHPublicKey(DHPublicKeyIface):
  """An implementation of the DHPublicKey Interface."""
  KEY_LEN = 56

  def __init__(self, public_key):
    if not isinstance(public_key, X448PublicKey):
      raise TypeError("public_key must be of type: X448PublicKey")
    self._public_key = public_key

  def pk_bytes(self):
    return pk_bytes(self._public_key)

  def is_equal_to(self, dh_pk):
    if not isinstance(dh_pk, DHPublicKey):
      raise TypeError("dh_pk must be of type: DHPublicKey")

    return self.pk_bytes() == dh_pk.pk_bytes()

  @classmethod
  def from_bytes(cls, pk_bytes):
    if not isinstance(pk_bytes, bytes):
      raise TypeError("pk_bytes must be of type: bytes")
    if not len(pk_bytes) == DHPublicKey.KEY_LEN:
      raise ValueError("pk_bytes must be 56 bytes")

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
    if not isinstance(serialized_pk, dict):
      raise TypeError("serialized_pk must be of type: dict")

    public_key = X448PublicKey.from_public_bytes(
      bytes.fromhex(serialized_pk["public_key"])
    )
    return cls(public_key)


# Returns public key in bytes form
def pk_bytes(pk):
  return pk.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
  )
