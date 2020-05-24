from __future__ import absolute_import

import pickle # for saving interface implemented params :|

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
  """Double Ratchet Session.
  
  Provides secure communication with peer session (initialized with same
  shared secrets) using Double Ratchet Algorithm.
  
  Session can be serialized/deserialized if desired.

  Reference: https://signal.org/docs/specifications/doubleratchet/
  """

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
    """Sets up new session and necessary Double Ratchet components.

    Args:
      state: State to initialize session with (ex. by deserializing 
        saved session).
      aead: a class implementating AEADIface.
      keypair: an instance of an implementation for DHKeyPairIface.
      public_key: an instance of an implementation for DHPublicKeyIface.
      keystorage: an instance of an implementation for MsgKeyStorageIface.
      root_chain: an instance of an implementation for RootChainIface.
      symmetric_chain: an instance of an implementation for SymmetricChainIface.
      ratchet: an instance of an implementation for RatchetIface.

    Raises:
      TypeError: on incorrect argument type.
    """

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
      sk: shared secret key (agreed upon using protocol such as X3DH).
      dh_pk_r: received DH-ratchet public key.

    Raises:
      TypeError: on incorrect argument type.
    """

    if not isinstance(sk, bytes):
      raise TypeError("sk must be of type: bytes")
    if not isinstance(dh_pk_r, DHPublicKey):
      raise TypeError("dh_pk_r must be of type: DHPublicKey")

    self._state.init_sender(sk, dh_pk_r)

  def setup_receiver(self, sk: bytes, dh_pair: DHKeyPair) -> None:
    """Sets up session as initial receiver.

    Args:
      sk: shared secret key (agreed upon using protocol such as X3DH).
      dh_pair: generated DH-ratchet keypair.
    
    Raises:
      TypeError: on incorrect argument type.
    """

    if not isinstance(sk, bytes):
      raise TypeError("sk must be of type: bytes")
    if not isinstance(dh_pair, DHKeyPair):
      raise TypeError("dh_pair must be of type: DHKeyPair")

    self._state.init_receiver(sk, dh_pair)

  def encrypt_message(self, pt: str, associated_data: bytes) -> Message:
    """Returns an encrypted message (header and ciphertext).

    Args:
      pt: plaintext to encrypt.
      associated_data: additional data to bind to ciphertext integrity.

    Raises:
      TypeError: on incorrect argument type.
    """
    
    if not isinstance(pt, str):
      raise TypeError("pt must be of type: string")
    if not isinstance(associated_data, bytes):
      raise TypeError("associated_data must be of type: bytes")

    msg = self._ratchet.encrypt_message(
      self._state, pt, associated_data, self._aead)
    return msg

  def decrypt_message(self, msg: Message, associated_data: bytes) -> str:
    """Returns decrypted message plaintext.

    Args:
      msg: header and ciphertext.
      associated_data: additional data bound to ciphertext integrity.

    Raises:
      TypeError: on incorrect argument type.
      AuthenticationFailed: on decryption failure.
    """

    if not isinstance(msg, Message):
      raise TypeError("msg must be of type: Message")
    if not isinstance(associated_data, bytes):
      raise TypeError("associated_data must be of type: bytes")

    pt = self._ratchet.decrypt_message(
      self._state, msg, associated_data, self._aead, self._keypair)
    return pt

  def generate_dh_keys(self) -> DHKeyPair:
    """Returns a new DHKeypair."""
    return self._keypair.generate_dh()

  def serialize(self) -> dict:
    """Returns serialized dictionary of session state."""
    return {
      "state" : self._state.serialize(),
      "aead": pickle.dumps(self._aead), # need to use pickle to save class types
      "keypair": pickle.dumps(self._keypair),
      "ratchet": pickle.dumps(self._ratchet)
    }

  @classmethod
  def deserialize(cls, serialized_dict: dict):
    """Returns new instance of DRSession from provided
    serialized state.
    
    Args:
      serialized_dict: serialized session state.
      
    Raises:
      TypeError: on incorrect argument type.
      """

    if not isinstance(serialized_dict, dict):
      raise TypeError("serialized_dict must be of type: dict")

    return cls(
      state=State.deserialize(serialized_dict["state"]),
      aead=pickle.loads(serialized_dict["aead"]), # need to use pickle to save class types
      keypair=pickle.loads(serialized_dict["keypair"]),
      ratchet=pickle.loads(serialized_dict["ratchet"])
    )


class DRSessionHE(SerializableIface):
  """Double Ratchet Session using Header Encryption.
  
  Provides secure communication with peer session (initialized with same
  shared secrets) using Double Ratchet Algorithm with header encryption.
  
  Session can be serialized/deserialized if desired.

  Reference: https://signal.org/docs/specifications/doubleratchet/
  """

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
    """Sets up new session and necessary Double Ratchet components.

    Args:
      state: State to initialize session with (ex. by deserializing 
        saved session).
      aead: a class implementating AEADIface.
      keypair: an instance of an implementation for DHKeyPairIface.
      public_key: an instance of an implementation for DHPublicKeyIface.
      keystorage: an instance of an implementation for MsgKeyStorageIface.
      root_chain: an instance of an implementation for RootChainIface.
      symmetric_chain: an instance of an implementation for SymmetricChainIface.
      ratchet: an instance of an implementation for RatchetIface.

    Raises:
      TypeError: on incorrect argument type.
    """

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

  def setup_sender(self, sk: bytes, dh_pk_r: DHPublicKey, hk_s: bytes,
      next_hk_r: bytes) -> None:
    """Sets up session as initial sender.

    Args:
      sk: shared secret key (agreed upon using protocol such as X3DH).
      dh_pk_r: received DH-ratchet public key.
      hk_s: shared header sending key (agreed upon using protocol such as X3DH).
      next_hk_r: shared next header receiving key (agreed upon using protocol 
        such as X3DH).

    Raises:
      TypeError: on incorrect argument type.
    """

    if not isinstance(sk, bytes):
      raise TypeError("sk must be of type: bytes")
    if not isinstance(dh_pk_r, DHPublicKey):
      raise TypeError("dh_pk_r must be of type: DHPublicKey")
    if not isinstance(hk_s, bytes):
      raise TypeError("hk_s must be of type: bytes")
    if not isinstance(next_hk_r, bytes):
      raise TypeError("next_hk_r must be of type: bytes")

    self._state.init_sender_he(sk, dh_pk_r, hk_s, next_hk_r)

  def setup_receiver(self, sk: bytes, dh_pair: DHKeyPair, 
      next_hk_s: bytes, next_hk_r: bytes) -> None:
    """Sets up session as initial receiver.

    Args:
      sk: shared secret key (agreed upon using protocol such as X3DH).
      dh_pair: generated DH-ratchet keypair.
      next_hk_s: shared next header sending key (agreed upon using protocol 
        such as X3DH).
      next_hk_r: shared next header receiving key (agreed upon using protocol 
        such as X3DH).
    
    Raises:
      TypeError: on incorrect argument type.
    """

    if not isinstance(sk, bytes):
      raise TypeError("sk must be of type: bytes")
    if not isinstance(dh_pair, DHKeyPair):
      raise TypeError("dh_pair must be of type: DHKeyPair")
    if not isinstance(next_hk_s, bytes):
      raise TypeError("next_hk_s must be of type: bytes")
    if not isinstance(next_hk_r, bytes):
      raise TypeError("next_hk_r must be of type: bytes")

    self._state.init_receiver_he(sk, dh_pair, next_hk_s, next_hk_r)

  def encrypt_message(self, pt: str, associated_data: bytes) -> Message:
    """Returns an encrypted message (header and ciphertext).

    Args:
      pt: plaintext to encrypt.
      associated_data: additional data to bind to ciphertext integrity.

    Raises:
      TypeError: on incorrect argument type.
    """
    
    if not isinstance(pt, str):
      raise TypeError("pt must be of type: string")
    if not isinstance(associated_data, bytes):
      raise TypeError("associated_data must be of type: bytes")

    msg = self._ratchet.encrypt_message(
      self._state, pt, associated_data, self._aead)
    return msg

  def decrypt_message(self, msg: Message, associated_data: bytes) -> str:
    """Returns decrypted message plaintext.

    Args:
      msg: header and ciphertext.
      associated_data: additional data bound to ciphertext integrity.

    Raises:
      TypeError: on incorrect argument type.
      AuthenticationFailed: on decryption failure.
    """

    if not isinstance(msg, Message):
      raise TypeError("msg must be of type: Message")
    if not isinstance(associated_data, bytes):
      raise TypeError("associated_data must be of type: bytes")

    pt = self._ratchet.decrypt_message(
      self._state, msg, associated_data, self._aead, self._keypair)
    return pt

  def generate_dh_keys(self) -> DHKeyPair:
    """Returns a new DHKeypair."""
    return self._keypair.generate_dh()

  def serialize(self) -> dict:
    """Returns serialized dictionary of session state."""
    return {
      "state" : self._state.serialize(),
      "aead": pickle.dumps(self._aead),
      "keypair": pickle.dumps(self._keypair),
      "ratchet": pickle.dumps(self._ratchet)
    }

  @classmethod
  def deserialize(cls, serialized_dict: dict):
    """Returns new instance of DRSession from provided
    serialized state.
    
    Args:
      serialized_dict: serialized session state.
      
    Raises:
      TypeError: on incorrect argument type.
    """
    if not isinstance(serialized_dict, dict):
      raise TypeError("serialized_dict must be of type: dict")

    return cls(
      state=State.deserialize(serialized_dict["state"]),
      aead=pickle.loads(serialized_dict["aead"]),
      keypair=pickle.loads(serialized_dict["keypair"]),
      ratchet=pickle.loads(serialized_dict["ratchet"])
    )
