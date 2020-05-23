from __future__ import absolute_import

import pickle

from .interfaces.aead import AEADIFace
from .interfaces.dhkey import DHKeyPairIface, DHPublicKeyIface
from .interfaces.kdfchain import RootChainIface, SymmetricChainIface
from .interfaces.keystorage import MsgKeyStorageIface
from .interfaces.ratchet import RatchetIface
from .interfaces.serializable import SerializableIface
from .crypto.aead import AES256CBCHMAC
from .crypto.dhkey import DHKeyPair, DHPublicKey
from .crypto.kdfchain import SymmetricChain, RootChain
from .keystorage import MsgKeyStorage
from .message import Message
from .ratchet import Ratchet
from .state import State


class DRSession(SerializableIface):
  """Double ratchet session."""

  # TODO: set default classes
  def __init__(
      self,
      state: State = None,
      aead: AEADIFace = AES256CBCHMAC, 
      keypair: DHKeyPairIface = DHKeyPair,
      public_key: DHPublicKeyIface = DHPublicKey,
      keystorage: MsgKeyStorageIface = MsgKeyStorage, 
      root_chain: RootChainIface = RootChain,
      symmetric_chain: SymmetricChainIface = SymmetricChain,
      ratchet: RatchetIface = Ratchet) -> None:

    if state and not isinstance(state, State):
      raise TypeError("state must be of type: State")
    if not issubclass(aead, AEADIFace):
      raise TypeError("aead must implement AEADIFace")
    if not issubclass(keypair, DHKeyPairIface):
      raise TypeError("keypair must implement DHKeyPairIface")
    if not issubclass(public_key, DHPublicKeyIface):
      raise TypeError("public_key must implement DHPublicKeyIface")
    if not issubclass(keystorage, MsgKeyStorageIface):
      raise TypeError("keystorage must implement MsgKeyStorageIface")
    if not issubclass(root_chain, RootChainIface):
      raise TypeError("root_chain must implement KDFChainIface")
    if not issubclass(symmetric_chain, SymmetricChainIface):
      raise TypeError("symmetric_chain must implement SymmetricChainIface")
    if not issubclass(ratchet, RatchetIface):
      raise TypeError("ratchet must be of type: RatchetIface")

    self._aead = aead
    self._keypair = keypair
    self._ratchet = ratchet

    if state:
      self._state = state
    else:
      self._state = \
        State(keypair, public_key, keystorage, root_chain, symmetric_chain)

  def setup_sender(self, sk: bytes, dh_pk_r: DHPublicKey) -> None:
    """Sets up session as initial sender.

    Args:
      sk: shared secret key, agreed upon using protocol such as X3DH.
      dh_pk_r: received DH-ratchet public key.
    """

    if not isinstance(sk, bytes):
      raise TypeError("sk must be of type: bytes")
    if not isinstance(dh_pk_r, DHPublicKey):
      raise TypeError("dh_pk_r must be of type: DHPublicKey")

    self._state.init_sender(sk, dh_pk_r)

  def setup_receiver(self, sk: bytes, dh_pair: DHKeyPair) -> None:
    """Sets up session as initial receiver.

    Args:
      sk: shared secret key, agreed upon using protocol such as X3DH.
      dh_pair: generated DH-ratchet key pair.
    """

    if not isinstance(sk, bytes):
      raise TypeError("sk must be of type: bytes")
    if not isinstance(dh_pair, DHKeyPair):
      raise TypeError("dh_pair must be of type: DHKeyPair")

    self._state.init_receiver(sk, dh_pair)

  def encrypt_message(self, pt: str, associated_data: bytes) -> Message:
    """Returns an encrypted message.

    Args:
      pt: plaintext to encrypt.
      associated_data: additional data to bind to ciphertext integrity.

    Raises:
      Error: on message encryption failure the message is discarded
      and state reverted (ciphertext is None).
    """
    
    if not isinstance(pt, str):
      raise TypeError("pt must be of type: string")
    if not isinstance(associated_data, bytes):
      raise TypeError("associated_data must be of type: bytes")

    msg = self._ratchet.encrypt_message(
      self._state, pt, associated_data, self._aead)
    return msg

  def decrypt_message(self, msg: Message, associated_data: bytes) -> str:
    """Returns an plaintext message.

    Args:
      msg: encrypted message (ciphertext).
      associated_data: additional data bound to ciphertext integrity.

    Raises:
      Error: on message decryption failure the message is discarded
      and state reverts.
    """

    if not isinstance(msg, Message):
      raise TypeError("msg must be of type: Message")
    if not isinstance(associated_data, bytes):
      raise TypeError("associated_data must be of type: bytes")

    pt = self._ratchet.decrypt_message(
      self._state, msg, associated_data, self._aead, self._keypair)
    return pt

  def generate_dh_keys(self) -> DHKeyPair:
    """TODO:"""
    return self._keypair.generate_dh()

  def serialize(self) -> dict:
    return {
      "state" : self._state.serialize(),
      "aead": pickle.dumps(self._aead),
      "keypair": pickle.dumps(self._keypair),
      "ratchet": pickle.dumps(self._ratchet)
    }

  @classmethod
  def deserialize(cls, serialized_dict: dict):
    return cls(
      state=State.deserialize(serialized_dict["state"]),
      aead=pickle.loads(serialized_dict["aead"]),
      keypair=pickle.loads(serialized_dict["keypair"]),
      ratchet=pickle.loads(serialized_dict["ratchet"])
    )
