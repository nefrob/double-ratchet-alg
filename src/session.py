from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

from .message import MessageHE
from .state import State
from .ratchet import init_sender_he, init_receiver_he, ratchet_encrypt_he, \
  ratchet_decrypt_he
from .crypto import gen_dh_keys

class DRSessionHE:
  """Double ratchet session with encrypted headers."""

  def __init__(self):
      self.state = State()

  def setup_sender(self, sk: bytes, dh_pk_r: X448PublicKey, hk_s: bytes,
      next_hk_r: bytes):
    """Sets up session as initial sender.

    Args:
      sk: shared secret key, agreed upon using protocol such as X3DH.
      dh_pk_r: received DH-ratchet public key.
      hk_s: header sending key, agreed upon using protocol such as X3DH.
      next_hk_r: next header receiving key, agreed upon using protocol such as X3DH.
    """

    if not isinstance(sk, bytes):
      raise Exception("Error: sk must be in 'bytes'.")
    if not isinstance(dh_pk_r, X448PublicKey):
      raise Exception("Error: dh_pk_r must be a 'X448PublicKey'.")
    if not isinstance(hk_s, bytes):
      raise Exception("Error: hk_s must be in 'bytes'.")
    if not isinstance(next_hk_r, bytes):
      raise Exception("Error: next_hk_r must be in 'bytes'.")

    init_sender_he(self.state, sk, dh_pk_r, hk_s, next_hk_r)

  def setup_receiver(self, sk: bytes, dh_pair: X448PrivateKey, 
      next_hk_s: bytes, next_hk_r: bytes):
    """Sets up session as initial receiver.

    Args:
      sk: shared secret key, agreed upon using protocol such as X3DH.
      dh_pair: generated DH-ratchet key pair.
      next_hk_s: next header sending key, agreed upon using protocol such as X3DH.
      next_hk_r: next header receiving key, agreed upon using protocol such as X3DH.
    """

    if not isinstance(sk, bytes):
      raise Exception("Error: sk must be in 'bytes'.")
    if not isinstance(dh_pair, X448PrivateKey):
      raise Exception("Error: dh_pair must be a 'X448PrivateKey'.")
    if not isinstance(next_hk_s, bytes):
      raise Exception("Error: next_hk_s must be in 'bytes'.")
    if not isinstance(next_hk_r, bytes):
      raise Exception("Error: next_hk_r must be in 'bytes'.")

    init_receiver_he(self.state, sk, dh_pair, next_hk_s, next_hk_r)

  def encrypt_message(self, pt: str, associated_data: bytes):
    """Returns an encrypted message.

    Args:
      pt: plaintext to encrypt.
      associated_data: additional data to bind to ciphertext integrity.

    Raises:
      Error: on header or message encryption failure the message is discarded
      and state reverted (ciphertext is None).
    """
    
    if not isinstance(pt, str):
      raise Exception("Error: pt must be a 'string'.")
    if not isinstance(associated_data, bytes):
        raise Exception("Error: associated_data must be in 'bytes'.")

    msg = ratchet_encrypt_he(self.state, pt, associated_data)
    if msg == None:
      raise Exception("Error: failed to encrypt message.")

    return msg

  def decrypt_message(self, msg: MessageHE, associated_data: bytes):
    """Returns an plaintext message.

    Args:
      msg: encrypted message (header & ciphertext).
      associated_data: additional data bound to ciphertext integrity.

    Raises:
      Error: on header or message decryption failure the message is discarded
      and state reverteds.
    """

    if not isinstance(msg, MessageHE):
      raise Exception("Error: msg must be a 'MessageHE'.")
    if not isinstance(associated_data, bytes):
      raise Exception("Error: associated_data must be 'bytes'.")
    
    pt = ratchet_decrypt_he(self.state, msg, associated_data)
    if pt == None:
      raise Exception("Error: failed to decrypt message.")
    return pt


def generate_dh_keys():
  """Returns new DH key pair."""

  return gen_dh_keys() 