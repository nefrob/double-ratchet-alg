from __future__ import absolute_import

from abc import abstractmethod

from .serializable import SerializableIface


class KDFChainIface(SerializableIface):
  """KDF Chain Interface."""

  @property
  @abstractmethod
  def ck(self):
    """Returns chain key."""
    pass

  @ck.setter
  @abstractmethod
  def ck(self, val):
    """Sets chain key to val."""
    pass

class SymmetricChainIface(KDFChainIface):
  """Symmetric KDF Chain Interface (extends KDFChain Interface)."""

  @abstractmethod
  def ratchet(self):
    """Ratchets the KDF chain, updating the chain key."""
    pass

  @property
  @abstractmethod
  def msg_no(self):
    """Returns the current chain message number (chain length)."""
    pass

  @msg_no.setter
  @abstractmethod
  def msg_no(self, val):
    """Sets the current message number to val."""
    pass

class RootChainIface(KDFChainIface):
  """Root KDF Chain Interface (extends KDFChain Interface)."""

  @abstractmethod
  def ratchet(self, dh_out):
    """Ratchets the KDF chain, updating the chain key."""
    pass
