from __future__ import absolute_import

from abc import abstractmethod

from .serializable import SerializableIface


# Note: suggested to use Curve25519 or Curve448
class DHKeyPairIface(SerializableIface):
  """Diffie-Hellman Keypair"""

  @classmethod
  @abstractmethod
  def generate_dh(cls):
    """Generates a new Diffie-Hellman keypair (containing private and 
    public keys)."""
    pass

  @abstractmethod
  def dh_out(self, dh_pk):
    """Returns Diffie-Hellman output from private key and provided peer
    public key."""
    pass

  @property
  @abstractmethod
  def private_key(self):
    """Returns Diffie-Hellman private key."""
    pass

  @property
  @abstractmethod
  def public_key(self):
    """Returns Diffie-Hellman public key."""  
    pass


class DHPublicKeyIface(SerializableIface):
  """Diffie-Hellman Public Key"""

  @abstractmethod
  def pk_bytes(self):
    """Returns Diffie-Hellman public key in byte form."""
    pass

  @abstractmethod
  def is_equal_to(self, dh_pk):
    """Checks if public key is equal to the provided one."""
    pass

  @classmethod
  @abstractmethod
  def from_bytes(cls, pk_bytes):
    """Returns Diffie-Hellman public key instance from byte form
    public key."""
    pass

  @property
  @abstractmethod
  def public_key(self):
    """Returns Diffie-Hellman public key."""
    pass
